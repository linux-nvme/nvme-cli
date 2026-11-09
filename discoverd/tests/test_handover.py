#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This file is part of nvme-cli.
# Copyright (c) 2026 SUSE LLC
#
# Authors: Daniel Wagner <dwagner@suse.de>
"""The hand-over from the pre-OS environment to nvme-discoverd.

Each test boots a host (handover.Host): the pre-OS environment connects
the boot paths with the real nvme, as dracut does, and after switch-root
nvme-discoverd takes over in a sandbox. The expectations follow the model
of issue #4328: what the pre-OS environment connected stays connected,
with its parameters, also over a restart, a reload and the shutdown.

Where today's behaviour differs from the model, the test is an expected
failure and says why. It starts to pass when the gap is closed.

Usage: NVME_DISCOVERD=<nvme-discoverd> python3 test_handover.py <nvme>
       <libmock_nvme.so>
"""
import unittest

from handover import DISC_NQN, Host
from tests.cli.nvme_mock import main

# NBFT-static-ipv4: one TCP boot subsystem, and the firmware's host.
NBFT_TABLE = 'NBFT-static-ipv4'
NBFT_NQN = 'nqn.2022-12.org.nvmexpress.boot.poc:bremer.vagrant-nvmet.subsys02'
NBFT_TRADDR = '192.168.49.10'
NBFT_HOST_TRADDR = '192.168.49.50'
NBFT_HOST_ID = 'e359b7a1-5d03-7747-b3cc-1754b8b819b9'
NBFT_HOST_NQN = ('nqn.2014-08.org.nvmexpress:uuid:'
                 'a1b759e3-035d-4777-b3cc-1754b8b819b9')

IO_NQN = 'nqn.2026-11.org.example:data'
IO_TRADDR = '192.0.2.20'

FC_DC = 'nn-0x200000109b000001:pn-0x100000109b000001'
FC_IO = 'nn-0x200000109b000002:pn-0x100000109b000002'
FC_HOST = 'nn-0x20000090fa000001:pn-0x10000090fa000001'


class HandoverTest(unittest.TestCase):

    def setUp(self):
        self.host = Host()
        self.addCleanup(self.host.close)

    # -- the pre-OS environment ---------------------------------------- #

    def boot_nbft(self, firmware_identity=True):
        """Boot from the NBFT, as dracut runs "nvme connect-all --nbft".
        With @firmware_identity, the host's /etc/nvme/hostnqn is the one
        the firmware has; otherwise the host has its own."""
        host = self.host
        host.fabric.add_target('tcp', NBFT_TRADDR, '4420', NBFT_NQN)
        host.nbft(NBFT_TABLE)
        if firmware_identity:
            (host.base / 'hostnqn').write_text(f'{NBFT_HOST_NQN}\n',
                                               encoding='utf-8')
            (host.base / 'hostid').write_text(f'{NBFT_HOST_ID}\n',
                                              encoding='utf-8')
        res = host.nvme('connect-all', '--nbft',
                        f'--nbft-path={host.sysfs}/sys/firmware/acpi/tables')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(len(host.find(NBFT_NQN)), 1)
        host.discoverd_config('[Global]\nnbft = true\n')
        return host.find(NBFT_NQN)[0]

    def fc_fabric(self):
        """An FC DC whose Discovery Log Page lists one I/O subsystem."""
        self.host.fabric.add_target(
            'fc', FC_DC, '', DISC_NQN, host_traddr=FC_HOST,
            dlp=[{'transport': 'fc', 'traddr': FC_IO, 'trsvcid': '',
                  'subsysnqn': IO_NQN}])
        self.host.fabric.add_target('fc', FC_IO, '', IO_NQN,
                                    host_traddr=FC_HOST)

    def boot_fc(self):
        """FC boot connections, as dracut's FC kickstart runs connect-all
        for the DC. They have no owner."""
        self.fc_fabric()
        res = self.host.nvme('connect-all', '--transport=fc',
                             f'--traddr={FC_DC}',
                             f'--host-traddr={FC_HOST}')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(len(self.host.find(IO_NQN)), 1)
        return self.host.find(IO_NQN)[0]

    def configure_io(self, extra=''):
        self.host.fabric.add_target('tcp', IO_TRADDR, '4420', IO_NQN)
        self.host.fabrics_conf(
            f'[Subsystem]\nnqn = {IO_NQN}\n{extra}'
            f'controller = transport=tcp;traddr={IO_TRADDR};trsvcid=4420\n')

    def connect_io(self, *args):
        res = self.host.nvme('connect', '-t', 'tcp', '-a', IO_TRADDR,
                             '-s', '4420', '-n', IO_NQN, *args)
        self.assertEqual(res.returncode, 0, res.stderr)
        return self.host.find(IO_NQN)[0]

    def tracked(self, devname):
        return [c for c in self.host.daemon.dump()
                if c['devname'] == devname]

    # -- A: the hand-over ---------------------------------------------- #

    def test_a1_nbft_adopted(self):
        """The NBFT boot path is adopted with owner nbft, not connected
        again."""
        dev = self.boot_nbft()
        self.assertEqual(self.host.owner(dev), 'nbft')
        self.host.start()
        self.assertEqual(self.host.find(NBFT_NQN), [dev])
        self.assertEqual(self.host.owner(dev), 'nbft')
        ctrls = self.tracked(dev)
        self.assertEqual(len(ctrls), 1)
        self.assertTrue(ctrls[0]['nbft'])
        self.assertEqual(self.host.disconnected, [])

    def test_a1_nbft_firmware_host_identity(self):
        """The boot path connects as the firmware's host, as nvme-cli 2
        did, also when the system has a host NQN of its own (fixed by
        #4384). After switch-root, nvme-discoverd connects as the NBFT's
        host too, and the kernel makes no second controller to the boot
        subsystem."""
        dev = self.boot_nbft(firmware_identity=False)
        self.assertEqual(self.host.ctrl(dev)['hostnqn'], NBFT_HOST_NQN)
        self.host.start()
        self.assertEqual(self.host.find(NBFT_NQN), [dev])

    def test_a2_nbft_disabled(self):
        """With nbft = false, the boot path is not touched."""
        dev = self.boot_nbft()
        self.host.discoverd_config('[Global]\nnbft = false\n')
        self.host.start()
        self.assertEqual(self.host.find(NBFT_NQN), [dev])
        self.assertEqual(self.host.daemon.dump(), [])
        self.assertEqual(self.host.unit_starts(), [])

    def test_a3_fc_boot_path_adopted(self):
        """An unowned FC boot connection that nvme-discoverd wants is
        adopted with owner discoverd, not connected again."""
        dev = self.boot_fc()
        self.assertIsNone(self.host.owner(dev))
        self.host.start()
        self.assertEqual(self.host.find(IO_NQN), [dev])
        self.assertEqual(self.host.owner(dev), 'discoverd')
        self.assertEqual(len(self.tracked(dev)), 1)
        self.assertNotIn(dev, self.host.disconnected)

    def test_a4_unwanted_connection_left_alone(self):
        """A connection nvme-discoverd does not want is not touched."""
        self.host.fabric.add_target('tcp', IO_TRADDR, '4420', IO_NQN)
        dev = self.connect_io()
        self.host.start()
        self.host.shutdown()
        self.assertEqual(self.host.find(IO_NQN), [dev])
        self.assertIsNone(self.host.owner(dev))
        self.assertEqual(self.host.unit_starts(), [])

    @unittest.expectedFailure
    def test_a5_preos_parameters_kept(self):
        """A connection the pre-OS environment made keeps its parameters.
        The initrd connects without an owner, so nvme-discoverd adopts it
        and connects it with the configured parameters when it is lost."""
        self.configure_io('ctrl-loss-tmo = 60\n')
        dev = self.connect_io('--ctrl-loss-tmo=-1')
        self.host.start()
        self.host.lose(dev)
        (dev,) = self.host.find(IO_NQN)
        self.assertEqual(self.host.ctrl(dev)['ctrl_loss_tmo'], '-1')

    def test_a6_nbft_without_registry(self):
        """An initrd with nvme-cli 2 records no owner. The NBFT boot path
        is still adopted as nbft, not connected again."""
        host = self.host
        host.fabric.add_target('tcp', NBFT_TRADDR, '4420', NBFT_NQN)
        host.nbft(NBFT_TABLE)
        dev = host.plant('tcp', NBFT_TRADDR, '4420', NBFT_NQN,
                         host_traddr=NBFT_HOST_TRADDR,
                         hostnqn=NBFT_HOST_NQN, hostid=NBFT_HOST_ID)
        host.discoverd_config('[Global]\nnbft = true\n')
        host.start()
        self.assertEqual(host.find(NBFT_NQN), [dev])
        self.assertEqual(host.owner(dev), 'nbft')

    def test_a7_nbft_path_lost_before_switch_root(self):
        """A boot path the initrd connected and lost before switch-root is
        connected again, with owner nbft."""
        host = self.host
        host.fabric.add_target('tcp', NBFT_TRADDR, '4420', NBFT_NQN)
        host.nbft(NBFT_TABLE)
        reg = host.base / 'registry/nvme0'
        reg.mkdir(parents=True)
        (reg / 'owner').write_text('nbft\n', encoding='utf-8')
        host.discoverd_config('[Global]\nnbft = true\n')
        host.start()
        (dev,) = host.find(NBFT_NQN)
        self.assertEqual(host.owner(dev), 'nbft')
        self.assertEqual(host.ctrl(dev)['hostnqn'], NBFT_HOST_NQN)

    def test_a8_other_owner_skipped(self):
        """A controller another orchestrator owns is not touched."""
        self.configure_io()
        dev = self.connect_io('--owner=stas')
        self.host.start()
        self.host.shutdown()
        self.assertEqual(self.host.find(IO_NQN), [dev])
        self.assertEqual(self.host.owner(dev), 'stas')
        self.assertEqual(self.host.unit_starts(), [])

    # -- B: the OS environment keeps the boot paths -------------------- #

    def test_b1_restart(self):
        """A restart of nvme-discoverd neither disconnects a boot path nor
        connects it again."""
        dev = self.boot_nbft()
        self.host.start()
        starts = len(self.host.unit_starts())
        self.host.restart()
        self.assertEqual(self.host.find(NBFT_NQN), [dev])
        self.assertEqual(len(self.host.unit_starts()), starts)
        self.assertEqual(self.host.disconnected, [])
        self.assertEqual(len(self.tracked(dev)), 1)

    def test_b1_nbft_path_lost(self):
        """A lost boot path is connected again, with owner nbft."""
        dev = self.boot_nbft()
        self.host.start()
        self.host.lose(dev)
        (dev,) = self.host.find(NBFT_NQN)
        self.assertEqual(self.host.owner(dev), 'nbft')
        self.assertEqual(len(self.tracked(dev)), 1)

    def configure_fc(self, extra=''):
        """The FC DC in the fabrics configuration, not the pre-OS
        environment's."""
        self.fc_fabric()
        self.host.fabrics_conf(
            f'[Discovery Controller]\n{extra}'
            f'controller = transport=fc;traddr={FC_DC};'
            f'host-traddr={FC_HOST}\n')

    def test_b7_dc_parked_again(self):
        """A DC with EPCSD=0 is parked after its DLP is read, also after
        a re-check whose reconnect gets the name back that parking freed:
        the old device's remove event is ignored then, and nvme-discoverd
        must not take the new device for it."""
        self.configure_fc()
        self.host.start()
        self.assertEqual(self.host.find(DISC_NQN), [])
        (dev,) = self.host.find(IO_NQN)
        self.assertEqual(self.host.owner(dev), 'discoverd')

    def test_b7_fc_path_lost_persistent_dc(self):
        """An FC I/O controller that is deleted (dev_loss_tmo) behind a
        persistent DC, which stays connected and has no timer, is
        connected again: the FC kickstart makes nvme-discoverd read the
        DC's DLP."""
        self.configure_fc('persistent = force\n')
        self.host.start()
        self.assertEqual(len(self.host.find(DISC_NQN)), 1)
        (dev,) = self.host.find(IO_NQN)
        self.host.lose(dev)
        (dev,) = self.host.find(IO_NQN)
        self.assertEqual(self.host.owner(dev), 'discoverd')

    def test_b2_reload_drops_configured_boot_path(self):
        """A configuration reload that drops a connection the initrd made
        releases it without a disconnect."""
        self.configure_io()
        dev = self.connect_io()
        self.host.start()
        self.assertEqual(self.host.owner(dev), 'discoverd')
        self.host.fabrics_conf('')
        self.host.reload()
        self.assertEqual(self.host.find(IO_NQN), [dev])
        self.assertIsNone(self.host.owner(dev))
        self.assertEqual(self.host.loaded_units(), [])
        self.assertEqual(self.host.disconnected, [])

    def test_b3_exclusion_keeps_nbft_path(self):
        """An exclusion of the boot subsystem does not disconnect the boot
        path."""
        dev = self.boot_nbft()
        self.host.start()
        (self.host.base / 'exclusions.conf').write_text(
            f'[Exclusion]\nnqn = {NBFT_NQN}\n', encoding='utf-8')
        self.host.reload()
        self.assertEqual(self.host.find(NBFT_NQN), [dev])
        self.assertEqual(self.host.disconnected, [])

    def test_b4_fc_discovery_storm(self):
        """FC discovery events for a DC that is already known connect its
        I/O controller once."""
        self.fc_fabric()
        self.host.start()
        self.assertEqual(len(self.host.find(IO_NQN)), 1)
        for _ in range(5):
            self.host.fc_discovery(FC_DC, FC_HOST)
        self.assertEqual(len(self.host.find(IO_NQN)), 1)
        io = [c for c in self.host.fabric.connects if c['nqn'] == IO_NQN]
        self.assertEqual(len(io), 1)

    def test_b5_aen_from_preos_dc(self):
        """An AEN from a persistent DC the initrd connected, which has no
        owner, makes nvme-discoverd run connect-all for it. The boot path
        behind it is not connected again."""
        host = self.host
        host.fabric.add_target(
            'tcp', '192.0.2.10', '8009', DISC_NQN,
            dlp=[{'transport': 'tcp', 'traddr': IO_TRADDR,
                  'trsvcid': '4420', 'subsysnqn': IO_NQN}])
        host.fabric.add_target('tcp', IO_TRADDR, '4420', IO_NQN)
        res = host.nvme('connect-all', '-t', 'tcp', '-a', '192.0.2.10',
                        '-s', '8009', '--persistent=force')
        self.assertEqual(res.returncode, 0, res.stderr)
        (dc,) = host.find(DISC_NQN)
        (dev,) = host.find(IO_NQN)
        host.start()
        host.aen(dc)
        starts = [j['unit'] for j in host.unit_starts()]
        self.assertTrue(any('connect-all' in u for u in starts), starts)
        self.assertEqual(host.find(IO_NQN), [dev])
        self.assertEqual(host.find(DISC_NQN), [dc])
        self.assertEqual(host.disconnected, [])

    # -- C: the shutdown ----------------------------------------------- #

    @unittest.expectedFailure
    def test_c1_shutdown_keeps_nbft_path(self):
        """The shutdown does not disconnect the boot path (#4331). The
        unit nvme-discoverd adopted it into disconnects on stop."""
        dev = self.boot_nbft()
        self.host.start()
        self.host.shutdown()
        self.assertEqual(self.host.find(NBFT_NQN), [dev])

    @unittest.expectedFailure
    def test_c1_shutdown_keeps_fc_boot_path(self):
        """The shutdown does not disconnect the FC boot path (#4331)."""
        dev = self.boot_fc()
        self.host.start()
        self.host.shutdown()
        self.assertEqual(self.host.find(IO_NQN), [dev])

    def test_c1_shutdown_disconnects_own_connections(self):
        """What nvme-discoverd connected itself is disconnected at
        shutdown, by its units."""
        self.configure_io()
        self.host.start()
        (dev,) = self.host.find(IO_NQN)
        self.host.shutdown()
        self.assertEqual(self.host.find(IO_NQN), [])
        self.assertIn(dev, self.host.disconnected)


if __name__ == '__main__':
    main()
