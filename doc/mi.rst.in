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
