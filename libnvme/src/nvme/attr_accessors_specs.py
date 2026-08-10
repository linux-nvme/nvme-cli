# SPDX-License-Identifier: LGPL-2.1-or-later
"""
attr_accessors_specs.py — Input dicts for generate_attr_accessors.py.

One dict per opaque, lazily-loaded struct. Every dict must be added to
ATTR_SPECS at the bottom of this file -- that is the only thing
generate_attr_accessors.py actually imports; it generates every entry in
one run. See ../../design/tooling/generate_attr_accessors.md for the
schema each dict follows and how to add a new member.

Every entry's 'source'/'header'/'ld'/'swig'/'ld_section' keys must be
identical across the whole list -- generate_attr_accessors.py merges
every struct into one shared attr-accessors.{c,h,ld,i} set (plus
attr-accessors-{linux,win}.c for whichever structs have OS-divergent
members) rather than one file set per struct, so there is nothing to
choose per entry. 'ld_section' is 'LIBNVME_ATTR_ACCESSORS_NEXT', not a
real version number: the committed .ld is hand-written and never
auto-overwritten (see update-attr-accessors.sh), so this string only
ever appears in the generator's own scratch copy -- it is not diffed,
not enforced, and never echoed back to the maintainer. Which version
tag a symbol actually lands under is entirely the maintainer's call at
commit time (see accessor-workflow.md); a real-looking version number
here would just go stale the first time that tag chains past _3.
"""

_SHARED = {
    'source': 'attr-accessors.c',
    'header': 'attr-accessors.h',
    'ld': 'attr-accessors.ld',
    'swig': 'attr-accessors.i',
    'ld_section': 'LIBNVME_ATTR_ACCESSORS_NEXT',
}

CTRL_ATTRS = {
    **_SHARED,
    'struct_name': 'libnvme_ctrl_attrs',
    'owner_type': 'libnvme_ctrl',
    'owner_field': 'attrs',
    'attr_reader': 'libnvme_get_ctrl_attr',
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
            # attr-accessors-custom-linux.c / attr-accessors-custom-win.c.
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
            # Loader body varies by OS -- see attr-accessors-custom-linux.c /
            # attr-accessors-custom-win.c.
            'loader': 'libnvme_ctrl_load_phy_slot',
            'reconfigure_reset': True,
            'members': [
                'phy_slot',
            ],
        },
        {
            # Loader body varies by CONFIG_FABRICS (Linux only -- always
            # a no-op on Windows) -- see attr-accessors-custom-linux.c /
            # attr-accessors-custom-win.c.
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

PATH_ATTRS = {
    **_SHARED,
    'struct_name': 'libnvme_path_attrs',
    'owner_type': 'libnvme_path',
    'owner_field': 'attrs',
    'attr_reader': 'libnvme_get_path_attr',
    'source_linux': 'attr-accessors-linux.c',
    'source_win': 'attr-accessors-win.c',
    # No reconfigure_reset on any member: a path is never updated in
    # place on rescan -- libnvme_ctrl_scan_path() always calloc()s a new
    # one -- so there is no in-place-invalidate event these fields would
    # ever need to respond to. They live for the object's whole lifetime
    # and are freed only when the path itself is destroyed.
    #
    # Every member is 'win': {'absent': True} -- multipath, and so
    # struct libnvme_path itself, is a Linux-only concept. Windows still
    # needs every getter to exist and link (an app must not need
    # #ifdef _WIN32 to call them), so this is the simplest possible use
    # of a per-OS override: nothing to resolve, just no source.
    'members': [
        {
            'name': 'ana_state',
            'attr': 'ana_state',
            'type': 'char *',
            'volatile': True,
            'win': {'absent': True},
        },
        {
            'name': 'numa_nodes',
            'attr': 'numa_nodes',
            'type': 'char *',
            'win': {'absent': True},
        },
        {
            'name': 'grpid',
            'attr': 'ana_grpid',
            'type': 'int',
            'win': {'absent': True},
        },
        {
            'name': 'queue_depth',
            'attr': 'queue_depth',
            'type': 'int',
            'volatile': True,
            'win': {'absent': True},
        },
        {
            'name': 'multipath_failover_count',
            'attr': 'diag/multipath_failover_count',
            'type': 'long',
            'volatile': True,
            'win': {'absent': True},
        },
        {
            'name': 'command_retry_count',
            'attr': 'diag/command_retry_count',
            'type': 'long',
            'volatile': True,
            'win': {'absent': True},
        },
        {
            'name': 'command_error_count',
            'attr': 'diag/command_error_count',
            'type': 'long',
            'volatile': True,
            'win': {'absent': True},
        },
    ],
    'groups': [],
}

NS_ATTRS = {
    **_SHARED,
    'struct_name': 'libnvme_ns_attrs',
    'owner_type': 'libnvme_ns',
    'owner_field': 'attrs',
    'attr_reader': 'libnvme_get_ns_attr',
    # No reconfigure_reset on any member: like libnvme_path, an ns is
    # never updated in place on rescan -- libnvme_ctrl_scan_namespace()
    # always finds-or-frees the old one and installs a fresh one -- so
    # there is no in-place-invalidate event these fields would ever
    # need to respond to.
    'members': [
        # lba_size/lba_shift/lba_count/lba_util/meta_size/csi are all
        # 'custom': True -- the struct field (boxed, same NULL/
        # NO_ATTR/real-value tri-state every other cached numeric
        # member uses) and the header prototype are generated as usual,
        # but the getter body is hand-written in
        # attr-accessors-custom-<os>.c, not generated. Needed because
        # none of the three axes this generator understands (plain
        # attr, volatile attr, loader group) can express what these six
        # actually require: lba_shift
        # is derived from lba_size, not read from anywhere; the other
        # five each pick between two genuinely different sysfs-vs-
        # Identify sources at runtime, keyed by whether the "csi"
        # attribute exists (a runtime fact, not a build-time OS fact
        # the per-OS 'linux'/'win' override mechanism models).
        {
            'name': 'lba_size',
            'type': 'int',
            'custom': True,
        },
        {
            'name': 'lba_shift',
            'type': 'int',
            'custom': True,
        },
        {
            'name': 'lba_count',
            'type': 'uint64_t',
            'custom': True,
        },
        {
            'name': 'lba_util',
            'type': 'uint64_t',
            'custom': True,
        },
        {
            'name': 'meta_size',
            'type': 'int',
            'custom': True,
        },
        {
            'name': 'csi',
            'type': 'enum nvme_csi',
            'custom': True,
        },
        # eui64/nguid/uuid are also 'custom': True, and their raw type
        # is itself a pointer ("uint8_t *"/"unsigned char *") instead of
        # a plain scalar -- a cached fixed-size byte buffer, following
        # exactly the same storage-vs-public-type split a "char *"
        # string member gets: the struct field stays a plain mutable
        # pointer (see emit_struct_def()'s "already a pointer" branch),
        # while the public getter hands back a pointer-to-const view of
        # it (see _pub_type()) -- int fn(p, const TYPE **val, const
        # TYPE *dflt), same shape as any other lazy getter, no new axis
        # needed. Bodies are hand-written in
        # attr-accessors-custom-linux.c (real sysfs reads) and
        # attr-accessors-custom-win.c (always -ENOENT, Windows never had
        # a source for these either -- same as csi's Windows getter).
        {
            'name': 'eui64',
            'type': 'uint8_t *',
            'custom': True,
        },
        {
            'name': 'nguid',
            'type': 'uint8_t *',
            'custom': True,
        },
        {
            'name': 'uuid',
            'type': 'unsigned char *',
            'custom': True,
        },
        # The four diag/* counters need no per-OS override: like most
        # CTRL_ATTRS members, Windows absence falls out of the existing
        # libnvme_get_ns_attr() stub (unconditionally NULL) for free --
        # unlike PATH_ATTRS, libnvme_ns as a whole is not Windows-absent
        # (the six custom members above have real Windows sources), so
        # there is no reason to mark these explicitly absent either.
        {
            'name': 'command_retry_count',
            'attr': 'diag/command_retry_count',
            'type': 'long',
            'volatile': True,
        },
        {
            'name': 'command_error_count',
            'attr': 'diag/command_error_count',
            'type': 'long',
            'volatile': True,
        },
        {
            'name': 'io_requeue_no_usable_path_count',
            'attr': 'diag/io_requeue_no_usable_path_count',
            'type': 'long',
            'volatile': True,
        },
        {
            'name': 'io_fail_no_available_path_count',
            'attr': 'diag/io_fail_no_available_path_count',
            'type': 'long',
            'volatile': True,
        },
    ],
    'groups': [],
}

SUBSYS_ATTRS = {
    **_SHARED,
    'struct_name': 'libnvme_subsystem_attrs',
    'owner_type': 'libnvme_subsystem',
    'owner_field': 'attrs',
    'attr_reader': 'libnvme_get_subsys_attr',
    # No reconfigure_reset on any member: a subsystem is never updated
    # in place -- libnvme_get_subsystem() always looks up an existing
    # one by name/subsysnqn or creates a fresh one, there is no
    # deconfigure/rescan hook that touches an existing subsystem's
    # cached fields -- same rationale as PATH_ATTRS.
    'members': [
        # No group/loader needed, unlike CTRL_ATTRS's identity group:
        # Windows already has model/serial/firmware for free from the
        # ctrl map by the time a subsystem is scanned (no extra
        # Identify round trip to batch), so each is just a plain
        # attr member with writable=True and pushed in directly --
        # the exact "platform with no sysfs at all" backfill case
        # generate_attr_accessors.md's writable section already
        # names by example.
        {
            'name': 'model',
            'attr': 'model',
            'type': 'char *',
            'writable': True,
        },
        {
            'name': 'serial',
            'attr': 'serial',
            'type': 'char *',
            'writable': True,
        },
        {
            'name': 'firmware',
            'attr': 'firmware_rev',
            'type': 'char *',
            'writable': True,
        },
        # iopolicy can change at runtime (a user can rewrite the
        # sysfs attribute directly), so it is never cached -- matches
        # its pre-lazy hand-written getter, which always re-read
        # sysfs and only replaced the cached copy when the value
        # actually changed.
        {
            'name': 'iopolicy',
            'attr': 'iopolicy',
            'type': 'char *',
            'volatile': True,
        },
    ],
    'groups': [],
}

# generate_attr_accessors.py generates every entry here in one run.
ATTR_SPECS = [
    CTRL_ATTRS,
    PATH_ATTRS,
    NS_ATTRS,
    SUBSYS_ATTRS,
]
