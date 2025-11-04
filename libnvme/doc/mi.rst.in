NVMe Management Interface (NVMe-MI) support
===========================================

This libnvme project also includes support for the NVMe Management Interface
(NVMe-MI), currently over a Management Component Transport (MCTP)
protocol link. This MCTP link will typically use i2c/SMBus as the
hardware transport, enabling out-of-band management and control over NVMe
devices using a simple SMBus interface.

The MI interface is compiled into a separate shared object, ``libnvme-mi.so``.

Most of the MI API is transport-agnostic, except for the endpoint constructor
functions. Once an endpoint object (``nvme_mi_ep_t``) is created, the generic
functions can be used to manage it.

When endpoints are created (through one of the transport-specific functions,
like ``nvme_mi_open_mctp()``), the endpoint hardware will be probed to
see if any device-specific workarounds ("quirks") are required. This is
implemented as an Identify Controller command, requesting a small amount of
data on controller ID 0.

To suppress this probe, the ``LIBNVME_MI_PROBE_ENABLED`` environment var can be
set. Values of ``0``, ``false`` and ``disabled`` will disable the probe, and no
quirks will be applied. Other values, or an unset environment variable, will
enable the probe.

MCTP Transport
--------------

The MI API is generally transport-agnostic, but the only currently-supported
transport is MCTP, using the kernel ``AF_MCTP`` socket interface.

MCTP endpoints are addressed by a (network-id, endpoint-id) pair. Endpoint
IDs (EIDs) are defined by the MCTP standard as an 8-bit value. Since the
address space is somewhat limited, the Linux `AF_MCTP` support allows for
separate MCTP "networks", which provide separate address spaces. These networks
each have a unique ``unsigned int`` as their ID.

The default Network ID is 1; unless you have configured otherwise, MCTP
endpoints will appear on this network.

If compiled with D-Bus support, ``libnvme-mi`` can query the system MCTP daemon
("``mctpd``") to find attached NVMe devices, via the ``nvme_mi_scan_mctp()``
function. Calling this will establish a ``nvme_root_t`` object, populated
with the results of that scan. Use the ``nvme_mi_for_each_endpoint`` macro
to iterate through the scanned endpoints.

Note that the MCTP daemon is provided separately, as part of the MCTP userspace
tools, at https://github.com/CodeConstruct/mctp . ``mctpd`` is responsible for
discovery and enumeration for MCTP endpoints on the system, and will query
each for its protocol capabilities during enumeration. Consequently, NVMe-MI
endpoints will need to report support for NVMe-MI-over-MCTP (protocol 0x4) in
their supported protocols list (ie., as returned by the MCTP Get Message Type
Support command) in order to be discovered.
