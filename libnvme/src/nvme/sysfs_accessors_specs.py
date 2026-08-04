# SPDX-License-Identifier: LGPL-2.1-or-later
"""
sysfs_accessors_specs.py — Input dicts for generate_sysfs_accessors.py.

One dict per opaque, sysfs-backed struct. Every dict must be added to
SYSFS_SPECS at the bottom of this file -- that is the only thing
generate_sysfs_accessors.py actually imports; it generates every entry in
one run. See ../../design/tooling/generate_sysfs_accessors.md for the
schema each dict follows and how to add a new member.
"""

CTRL_SYSFS = {
    'struct_name': 'libnvme_ctrl_sysfs',
    'owner_type': 'libnvme_ctrl',
    'owner_field': 'sysfs',
    'source': 'ctrl-sysfs.c',
    'header': 'ctrl-sysfs.h',
    'ld': 'ctrl-sysfs.ld',
    'swig': 'ctrl-sysfs.i',
    # A distinct top-level tag, not LIBNVME_ACCESSORS_3: ld rejects two
    # --version-script files both defining the same tag (confirmed the
    # hard way -- "duplicate version tag" -- ctrl-sysfs.ld and
    # accessors.ld are separate generator outputs, so a shared tag isn't
    # achievable without hand-merging one into the other on every
    # regeneration of either). Matches the existing precedent of
    # accessors-fabrics.ld/libnvmf.ld/libnvme-mi.ld each having their
    # own independent tag rather than chaining.
    'ld_section': 'LIBNVME_CTRL_SYSFS_3',
    'members': [
        {
            'name': 'numa_node',
            'attr': 'numa_node',
            'type': 'char *',
            'reconfigure_reset': True,
        },
        {
            'name': 'queue_count',
            'attr': 'queue_count',
            'type': 'char *',
            'reconfigure_reset': True,
        },
        {
            'name': 'sqsize',
            'attr': 'sqsize',
            'type': 'char *',
            'reconfigure_reset': True,
        },
        {
            'name': 'command_error_count',
            'attr': 'diag/command_error_count',
            'type': 'long',
            'volatile': True,
        },
        {
            'name': 'reset_count',
            'attr': 'diag/reset_count',
            'type': 'long',
            'volatile': True,
        },
        {
            'name': 'reconnect_count',
            'attr': 'diag/reconnect_count',
            'type': 'long',
            'volatile': True,
        },
    ],
    'groups': [
        {
            # Linux: six independent sysfs reads (firmware_rev, model,
            # serial, cntrltype, cntlid, dctype). Windows: one real
            # Identify admin command (an actual device round trip),
            # since Windows has no sysfs to read these from at all --
            # grouped so a caller touching two of these fields never
            # triggers two Identify commands. writable=True (needed for
            # cntrltype/dctype's legacy-kernel fallback, see below)
            # applies to the whole group; firmware/model/serial/cntlid
            # get a setter they don't strictly need as a result -- a
            # deliberate tradeoff over splitting the group and risking
            # a second Identify call. Loader body varies by OS -- see
            # ctrl-sysfs-custom-linux.c / ctrl-sysfs-custom-win.c.
            'loader': 'libnvme_ctrl_load_identity',
            'reconfigure_reset': True,
            'writable': True,
            'members': [
                'firmware',
                'model',
                'serial',
                'cntrltype',
                'cntlid',
                'dctype',
            ],
        },
        {
            # Loader body varies by OS -- see ctrl-sysfs-custom-linux.c /
            # ctrl-sysfs-custom-win.c.
            'loader': 'libnvme_ctrl_load_phy_slot',
            'reconfigure_reset': True,
            'members': [
                'phy_slot',
            ],
        },
        {
            # Loader body varies by CONFIG_FABRICS -- see
            # ctrl-sysfs-custom-fabrics.c / ctrl-sysfs-custom-no-fabrics.c.
            'loader': 'libnvmf_ctrl_load_fabrics_attrs',
            'reconfigure_reset': True,
            'writable': True,
            'members': [
                'dhchap_host_key',
                'dhchap_ctrl_key',
                'keyring',
            ],
        },
    ],
}

# generate_sysfs_accessors.py generates every entry here in one run.
SYSFS_SPECS = [
    CTRL_SYSFS,
]
