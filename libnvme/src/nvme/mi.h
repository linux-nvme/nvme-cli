// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2021 Code Construct Pty Ltd
 *
 * Authors: Jeremy Kerr <jk@codeconstruct.com.au>
 */

/**
 * DOC: mi.h - NVMe Management Interface library (libnvme-mi) definitions.
 *
 * These provide an abstraction for the MI messaging between controllers
 * and a host, typically over an MCTP-over-i2c link to a NVMe device, used
 * as part of the out-of-band management of a system.
 *
 * We have a few data structures define here to reflect the topology
 * of a MI connection with an NVMe subsystem:
 *
 *  - &libnvme_mi_ep_t: an MI endpoint - our mechanism of communication with a
 *    NVMe subsystem. For MCTP, an endpoint will be the component that
 *    holds the MCTP address (EID), and receives our request message.
 *
 *    endpoints are defined in the NVMe-MI spec, and are specific to the MI
 *    interface.
 *
 *    Each endpoint will provide access to one or more of:
 *
 *  - &libnvme_mi_ctrl_t: a NVMe controller, as defined by the NVMe base spec.
 *    The controllers are responsible for processing any NVMe standard
 *    commands (eg, the Admin command set). An endpoint (&libnvme_mi_ep_t)
 *    may provide access to multiple controllers - so each of the controller-
 *    type commands will require a &libnvme_mi_ctrl_t to be specified, rather than
 *    an endpoint
 *
 * A couple of conventions with the libnvme-mi API:
 *
 *  - All types and functions have the libnvme_mi prefix, to distinguish from
 *    the libnvme core.
 *
 *  - We currently support either MI commands and Admin commands. The
 *    former adds a _mi prefix, the latter an _admin prefix. [This does
 *    result in the MI functions having a double _mi, like
 *    &libnvme_mi_mi_subsystem_health_status_poll, which is apparently amusing
 *    for our German-speaking readers]
 *
 * For return values: unless specified in the per-function documentation,
 * all functions:
 *
 *  - return 0 on success
 *
 *  - return -1, with errno set, for errors communicating with the MI device,
 *    either in request or response data
 *
 *  - return >1 on MI status errors. This value is the 8-bit MI status
 *    value, represented by &enum nvme_mi_resp_status. Note that the
 *    status values may be vendor-defined above 0xe0.
 *
 * For the second case, we have a few conventions for errno values:
 *
 *  - EPROTO: response data violated the MI protocol, and libnvme cannot
 *    validly interpret the response
 *
 *  - EIO: Other I/O error communicating with device (eg., valid but
 *    unexpected response data)
 *
 *  - EINVAL: invalid input arguments for a command
 *
 * In line with the core NVMe API, the Admin command functions take an
 * `_args` structure to provide the command-specific parameters. However,
 * for the MI interface, the fd and timeout members of these _args structs
 * are ignored.
 *
 * References to the specifications here will either to be the NVM Express
 * Management Interface ("NVMe-MI") or the NVM Express Base specification
 * ("NVMe"). At the time of writing, the versions we're referencing here
 * are:
 *  - NVMe-MI 1.2b
 *  - NVMe 2.0b
 * with a couple of accommodations for older spec types, particularly NVMe-MI
 * 1.1, where possible.
 *
 */
#pragma once

#include <nvme/mi-types.h>
#include <nvme/tree.h>

/**
 * libnvme_mi_status_to_string() - return a string representation of the MI
 * status.
 * @status: MI response status
 *
 * Gives a string description of @status, as per section 4.1.2 of the NVMe-MI
 * spec. The status value should be of type NVME_STATUS_MI, and extracted
 * from the return value using nvme_status_get_value().
 *
 * Returned string is const, and should not be free()ed.
 *
 * Returns: A string representing the status value
 */
const char *libnvme_mi_status_to_string(int status);

/* Top level management object: NVMe-MI Management Endpoint */
struct libnvme_mi_ep;

/**
 * typedef libnvme_mi_ep_t - MI Endpoint object.
 *
 * Represents our communication endpoint on the remote MI-capable device.
 * To be used for direct MI commands for the endpoint (through the
 * libnvme_mi_mi_* functions(), or to communicate with individual controllers
 * (see &libnvme_mi_init_ctrl).
 *
 * Endpoints are created through a transport-specific constructor; currently
 * only MCTP-connected endpoints are supported, through &libnvme_mi_open_mctp.
 * Subsequent operations on the endpoint (and related controllers) are
 * transport-independent.
 */
typedef struct libnvme_mi_ep * libnvme_mi_ep_t;

/**
 * libnvme_mi_set_csi - Assign a CSI to an endpoint.
 * @ep: Endpoint
 * @csi: value to use for CSI bit in NMP (0 or 1) for this endpoint
 *
 * Return: 0 if successful, -1 otherwise (some endpoints may not support)
 *
 */
int libnvme_mi_set_csi(libnvme_mi_ep_t ep, uint8_t csi);

/**
 * libnvme_mi_first_endpoint - Start endpoint iterator
 * @ctx:	&struct libnvme_global_ctx object
 *
 * Return: first MI endpoint object under this root, or NULL if no endpoints
 *         are present.
 *
 * See: &libnvme_mi_next_endpoint, &libnvme_mi_for_each_endpoint
 */
libnvme_mi_ep_t libnvme_mi_first_endpoint(struct libnvme_global_ctx *ctx);

/**
 * libnvme_mi_next_endpoint - Continue endpoint iterator
 * @ctx:	&struct libnvme_global_ctx object
 * @e: &libnvme_mi_ep_t current position of iterator
 *
 * Return: next endpoint MI endpoint object after @e under this root, or NULL
 *         if no further endpoints are present.
 *
 * See: &libnvme_mi_first_endpoint, &libnvme_mi_for_each_endpoint
 */
libnvme_mi_ep_t libnvme_mi_next_endpoint(struct libnvme_global_ctx *ctx, libnvme_mi_ep_t e);

/**
 * libnvme_mi_for_each_endpoint - Iterator for NVMe-MI endpoints.
 * @c: &struct libnvme_global_ctx object
 * @e: &libnvme_mi_ep_t object, set on each iteration
 */
#define libnvme_mi_for_each_endpoint(c, e)			\
	for (e = libnvme_mi_first_endpoint(c); e != NULL;	\
	     e = libnvme_mi_next_endpoint(c, e))

/**
 * libnvme_mi_for_each_endpoint_safe - Iterator for NVMe-MI endpoints, allowing
 * deletion during traversal
 * @c: &struct libnvme_global_ctx object
 * @e: &libnvme_mi_ep_t object, set on each iteration
 * @_e: &libnvme_mi_ep_t object used as temporary storage
 */
#define libnvme_mi_for_each_endpoint_safe(c, e, _e)			      \
	for (e = libnvme_mi_first_endpoint(c), _e = libnvme_mi_next_endpoint(c, e); \
	     e != NULL;							      \
	     e = _e, _e = libnvme_mi_next_endpoint(c, e))

/**
 * libnvme_mi_ep_set_timeout - set a timeout for NVMe-MI responses
 * @ep: MI endpoint object
 * @timeout_ms: Timeout for MI responses, given in milliseconds
 */
int libnvme_mi_ep_set_timeout(libnvme_mi_ep_t ep, unsigned int timeout_ms);

/**
 * libnvme_mi_ep_set_mprt_max - set the maximum wait time for a More Processing
 * Required response
 * @ep: MI endpoint object
 * @mprt_max_ms: Maximum more processing required wait time
 *
 * NVMe-MI endpoints may respond to a request with a "More Processing Required"
 * response; this also includes a hint on the worst-case processing time for
 * the eventual response data, with a specification-defined maximum of 65.535
 * seconds.
 *
 * This function provides a way to limit the maximum time we're prepared to
 * wait for the final response. Specify zero in @mprt_max_ms for no limit.
 * This should be larger than the command/response timeout set in
 * &libnvme_mi_ep_set_timeout().
 */
void libnvme_mi_ep_set_mprt_max(libnvme_mi_ep_t ep, unsigned int mprt_max_ms);

/**
 * libnvme_mi_ep_get_timeout - get the current timeout value for NVMe-MI responses
 * @ep: MI endpoint object
 *
 * Returns the current timeout value, in milliseconds, for this endpoint.
 */
unsigned int libnvme_mi_ep_get_timeout(libnvme_mi_ep_t ep);

/**
 * libnvme_mi_first_transport_handle - Start transport handle iterator
 * @ep: &libnvme_mi_ep_t object
 *
 * Return: first transport handle to a MI controller object under this
 *         root, or NULL if no controllers are present.
 *
 * See: &libnvme_mi_next_transport_handle, &libnvme_mi_for_each_transport_handle
 */
struct libnvme_transport_handle *libnvme_mi_first_transport_handle(libnvme_mi_ep_t ep);

/**
 * libnvme_mi_next_transport_handle - Continue transport handle iterator
 * @ep: &libnvme_mi_ep_t object
 * @hdl: &nvme_transport_handle current position of iterator
 *
 * Return: next transport handle to MI controller object after @c under
 *         this endpoint, or NULL if no further controllers are present.
 *
 * See: &libnvme_mi_first_transport_handle, &libnvme_mi_for_each_transport_handle
 */
struct libnvme_transport_handle *libnvme_mi_next_transport_handle(libnvme_mi_ep_t ep,
							    struct libnvme_transport_handle *hdl);

/**
 * libnvme_mi_for_each_transport_handle - Iterator for transport handle to NVMe-MI controllers.
 * @ep: &libnvme_mi_ep_t containing endpoints
 * @hdl: &nvme_trasnport_handle object, set on each iteration
 *
 * Allows iteration of the list of controllers behind an endpoint. Unless the
 * controllers have already been created explicitly, you'll probably want to
 * call &libnvme_mi_scan_ep() to scan for the controllers first.
 *
 * See: &libnvme_mi_scan_ep()
 */
#define libnvme_mi_for_each_transport_handle(ep, hdl)			\
	for (hdl = libnvme_mi_first_transport_handle(ep); hdl != NULL;	\
	     hdl = libnvme_mi_next_transport_handle(ep, hdl))

/**
 * libnvme_mi_for_each_transport_handle_safe - Iterator for transport handle to NVMe-MI controllers, allowing
 * deletion during traversal
 * @ep: &libnvme_mi_ep_t containing controllers
 * @hdl: &nvme_transport_handle object, set on each iteration
 * @_hdl: &nvme_transport_handle object used as temporary storage
 *
 * Allows iteration of the list of controllers behind an endpoint, safe against
 * deletion during iteration. Unless the controllers have already been created
 * explicitly (or you're just iterating to destroy controllers) you'll probably
 * want to call &libnvme_mi_scan_ep() to scan for the controllers first.
 *
 * See: &libnvme_mi_scan_ep()
 */
#define libnvme_mi_for_each_transport_handle_safe(ep, hdl, _hdl)		\
	for (hdl = libnvme_mi_first_transport_handle(ep),			\
	     _hdl = libnvme_mi_next_transport_handle(ep, hdl);		\
	     hdl != NULL;						\
	     hdl = _hdl, _hdl = libnvme_mi_next_transport_handle(ep, hdl))

/**
 * libnvme_mi_open_mctp() - Create an endpoint using a MCTP connection.
 * @ctx: &struct libnvme_global_ctx object
 * @netid: MCTP network ID on this system
 * @eid: MCTP endpoint ID
 *
 * Transport-specific endpoint initialization for MI-connected endpoints. Once
 * an endpoint is created, the rest of the API is transport-independent.
 *
 * Return: New endpoint object for @netid & @eid, or NULL on failure.
 *
 * See &libnvme_mi_close
 */
libnvme_mi_ep_t libnvme_mi_open_mctp(struct libnvme_global_ctx *ctx,
			       unsigned int netid, uint8_t eid);

/**
 * libnvme_mi_aem_open() - Prepare an existing endpoint to receive AEMs
 * @ep: Endpoint to configure for AEMs
 *
 * Return: 0 if success, -1 otherwise
 */
int libnvme_mi_aem_open(libnvme_mi_ep_t ep);

/**
 * libnvme_mi_close() - Close an endpoint connection and release resources,
 * including controller objects.
 *
 * @ep: Endpoint object to close
 */
void libnvme_mi_close(libnvme_mi_ep_t ep);

/**
 * libnvme_mi_scan_mctp - look for MCTP-connected NVMe-MI endpoints.
 *
 * Description: This function queries the system MCTP daemon ("mctpd") over
 * D-Bus, to find MCTP endpoints that report support for NVMe-MI over MCTP.
 *
 * This requires libvnme-mi to be compiled with D-Bus support; if not, this
 * will return NULL.
 *
 * Return: A @struct libnvme_global_ctx populated with a set of
 *         MCTP-connected endpoints, or NULL on failure
 */
struct libnvme_global_ctx *libnvme_mi_scan_mctp(void);

/**
 * libnvme_mi_scan_ep - query an endpoint for its NVMe controllers.
 * @ep: Endpoint to scan
 * @force_rescan: close existing controllers and rescan
 *
 * This function queries an MI endpoint for the controllers available, by
 * performing an MI Read MI Data Structure command (requesting the
 * controller list). The controllers are stored in the endpoint's internal
 * list, and can be iterated with libnvme_mi_for_each_ctrl.
 *
 * This will only scan the endpoint once, unless @force_rescan is set. If
 * so, all existing controller objects will be freed - the caller must not
 * hold a reference to those across this call.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise.
 *
 * See: &libnvme_mi_for_each_ctrl
 */
int libnvme_mi_scan_ep(libnvme_mi_ep_t ep, bool force_rescan);

/**
 * libnvme_mi_init_transport_handle() - initialise a transport handle to NVMe controller.
 * @ep: Endpoint to create under
 * @ctrl_id: ID of controller to initialize.
 *
 * Create a connection to a controller behind the endpoint specified in @ep.
 * Controller IDs may be queried from the endpoint through
 * &libnvme_mi_mi_read_mi_data_ctrl_list.
 *
 * Return: New transport handle object, or NULL on failure.
 *
 * See &libnvme_mi_close_transport_handle
 */
struct libnvme_transport_handle *libnvme_mi_init_transport_handle(libnvme_mi_ep_t ep, __u16 ctrl_id);

/**
 * libnvme_mi_ctrl_id() - get the ID of a controller
 * @hdl: transport handle to controller to query
 *
 * Retrieve the ID of the controller, as defined by hardware, and available
 * in the Identify (Controller List) data. This is the value passed to
 * @libnvme_mi_init_transport_handle, but may have been created internally via
 * @libnvme_mi_scan_ep.
 *
 * Return: the (locally-stored) ID of this controller.
 */
__u16 libnvme_mi_ctrl_id(struct libnvme_transport_handle *hdl);

/**
 * libnvme_mi_endpoint_desc - Get a string describing a MI endpoint.
 * @ep: endpoint to describe
 *
 * Generates a human-readable string describing the endpoint, with possibly
 * transport-specific data. The string is allocated during the call, and the
 * caller is responsible for free()-ing the string.
 *
 * Return: a newly-allocated string containing the endpoint description, or
 *         NULL on failure.
 */
char *libnvme_mi_endpoint_desc(libnvme_mi_ep_t ep);

/* MI Command API: libnvme_mi_mi_ prefix */

/**
 * libnvme_mi_mi_xfer() -  Raw mi transfer interface.
 * @ep: endpoint to send the MI command to
 * @mi_req: request data
 * @req_data_size: size of request data payload
 * @mi_resp: buffer for response data
 * @resp_data_size: size of response data buffer, updated to received size
 *
 * Performs an arbitrary NVMe MI command, using the provided request data,
 * in @mi_req. The size of the request data *payload* is specified in
 * @req_data_size - this does not include the standard header length (so a
 * header-only request would have a size of 0). Note that the Management
 * Request Doublewords are considered part of the header data.
 *
 * On success, response data is stored in @mi_resp, which has an optional
 * appended payload buffer of @resp_data_size bytes. The actual payload
 * size transferred will be stored in @resp_data_size. This size does not
 * include the MI response header, so 0 represents no payload.
 *
 * See: &struct nvme_mi_mi_req_hdr and &struct nvme_mi_mi_resp_hdr.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int libnvme_mi_mi_xfer(libnvme_mi_ep_t ep,
		       struct nvme_mi_mi_req_hdr *mi_req,
		       size_t req_data_size,
		       struct nvme_mi_mi_resp_hdr *mi_resp,
		       size_t *resp_data_size);

/**
 * libnvme_mi_mi_read_mi_data_subsys() - Perform a Read MI Data Structure command,
 * retrieving subsystem data.
 * @ep: endpoint for MI communication
 * @s: subsystem information to populate
 *
 * Retrieves the Subsystem information - number of external ports and
 * NVMe version information. See &struct nvme_mi_read_nvm_ss_info.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int libnvme_mi_mi_read_mi_data_subsys(libnvme_mi_ep_t ep,
				   struct nvme_mi_read_nvm_ss_info *s);

/**
 * libnvme_mi_mi_read_mi_data_port() - Perform a Read MI Data Structure command,
 * retrieving port data.
 * @ep: endpoint for MI communication
 * @portid: id of port data to retrieve
 * @p: port information to populate
 *
 * Retrieves the Port information, for the specified port ID. The subsystem
 * data (from &libnvme_mi_mi_read_mi_data_subsys) nmp field contains the allowed
 * range of port IDs.
 *
 * See &struct nvme_mi_read_port_info.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int libnvme_mi_mi_read_mi_data_port(libnvme_mi_ep_t ep, __u8 portid,
				 struct nvme_mi_read_port_info *p);

/**
 * libnvme_mi_mi_read_mi_data_ctrl_list() - Perform a Read MI Data Structure
 * command, retrieving the list of attached controllers.
 * @ep: endpoint for MI communication
 * @start_ctrlid: starting controller ID
 * @list: controller list to populate
 *
 * Retrieves the list of attached controllers, with IDs greater than or
 * equal to @start_ctrlid.
 *
 * See &struct nvme_ctrl_list.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int libnvme_mi_mi_read_mi_data_ctrl_list(libnvme_mi_ep_t ep, __u8 start_ctrlid,
				      struct nvme_ctrl_list *list);

/**
 * libnvme_mi_mi_read_mi_data_ctrl() - Perform a Read MI Data Structure command,
 * retrieving controller information
 * @ep: endpoint for MI communication
 * @ctrl_id: ID of controller to query
 * @ctrl: controller data to populate
 *
 * Retrieves the Controller Information Data Structure for the attached
 * controller with ID @ctrlid.
 *
 * See &struct nvme_mi_read_ctrl_info.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int libnvme_mi_mi_read_mi_data_ctrl(libnvme_mi_ep_t ep, __u16 ctrl_id,
				 struct nvme_mi_read_ctrl_info *ctrl);

/**
 * libnvme_mi_mi_subsystem_health_status_poll() - Read the Subsystem Health
 * Data Structure from the NVM subsystem
 * @ep: endpoint for MI communication
 * @clear: flag to clear the Composite Controller Status state
 * @nshds: subsystem health status data to populate
 *
 * Retrieves the Subsystem Health Data Structure into @nshds. If @clear is
 * set, requests that the Composite Controller Status bits are cleared after
 * the read. See NVMe-MI section 5.6 for details on the CCS bits.
 *
 * See &struct nvme_mi_nvm_ss_health_status.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int libnvme_mi_mi_subsystem_health_status_poll(libnvme_mi_ep_t ep, bool clear,
					    struct nvme_mi_nvm_ss_health_status *nshds);

/**
 * libnvme_mi_mi_config_get - query a configuration parameter
 * @ep: endpoint for MI communication
 * @dw0: management doubleword 0, containing configuration identifier, plus
 *       config-specific fields
 * @dw1: management doubleword 0, config-specific.
 * @nmresp: set to queried configuration data in NMRESP field of response.
 *
 * Performs a MI Configuration Get command, with the configuration identifier
 * as the LSB of @dw0. Other @dw0 and @dw1 data is configuration-identifier
 * specific.
 *
 * On a successful Configuration Get, the @nmresp pointer will be populated with
 * the bytes from the 3-byte NMRESP field, converted to native endian.
 *
 * See &enum nvme_mi_config_id for identifiers.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int libnvme_mi_mi_config_get(libnvme_mi_ep_t ep, __u32 dw0, __u32 dw1,
			  __u32 *nmresp);

/**
 * libnvme_mi_mi_config_set - set a configuration parameter
 * @ep: endpoint for MI communication
 * @dw0: management doubleword 0, containing configuration identifier, plus
 *       config-specific fields
 * @dw1: management doubleword 0, config-specific.
 *
 * Performs a MI Configuration Set command, with the command as the LSB of
 * @dw0. Other @dw0 and @dw1 data is configuration-identifier specific.
 *
 * See &enum nvme_mi_config_id for identifiers.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int libnvme_mi_mi_config_set(libnvme_mi_ep_t ep, __u32 dw0, __u32 dw1);

/**
 * libnvme_mi_mi_config_get_smbus_freq - get configuration: SMBus port frequency
 * @ep: endpoint for MI communication
 * @port: port ID to query
 * @freq: output value for current frequency configuration
 *
 * Performs a MI Configuration Get, to query the current SMBus frequency of
 * the port specified in @port. On success, populates @freq with the port
 * frequency
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
static inline int libnvme_mi_mi_config_get_smbus_freq(libnvme_mi_ep_t ep, __u8 port,
						   enum nvme_mi_config_smbus_freq *freq)
{
	__u32 tmp, dw0;
	int rc;

	dw0 = port << 24 | NVME_MI_CONFIG_SMBUS_FREQ;

	rc = libnvme_mi_mi_config_get(ep, dw0, 0, &tmp);
	if (!rc)
		*freq = (enum nvme_mi_config_smbus_freq)(tmp & 0x3);
	return rc;
}

/**
 * libnvme_mi_mi_config_set_smbus_freq - set configuration: SMBus port frequency
 * @ep: endpoint for MI communication
 * @port: port ID to set
 * @freq: new frequency configuration
 *
 * Performs a MI Configuration Set, to update the current SMBus frequency of
 * the port specified in @port.
 *
 * See &struct nvme_mi_read_port_info for the maximum supported SMBus frequency
 * for the port.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
static inline int libnvme_mi_mi_config_set_smbus_freq(libnvme_mi_ep_t ep, __u8 port,
						   enum nvme_mi_config_smbus_freq freq)
{
	__u32 dw0 = port << 24 |
		(freq & 0x3) << 8 |
		NVME_MI_CONFIG_SMBUS_FREQ;

	return libnvme_mi_mi_config_set(ep, dw0, 0);
}

/**
 * libnvme_mi_mi_config_set_health_status_change - clear CCS bits in health status
 * @ep: endpoint for MI communication
 * @mask: bitmask to clear
 *
 * Performs a MI Configuration Set, to update the current health status poll
 * values of the Composite Controller Status bits. Bits set in @mask will
 * be cleared from future health status poll data, and may be re-triggered by
 * a future health change event.
 *
 * See &libnvme_mi_mi_subsystem_health_status_poll(), &enum nvme_mi_ccs for
 * values in @mask.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
static inline int libnvme_mi_mi_config_set_health_status_change(libnvme_mi_ep_t ep,
							     __u32 mask)
{
	return libnvme_mi_mi_config_set(ep, NVME_MI_CONFIG_HEALTH_STATUS_CHANGE,
				     mask);
}

/**
 * libnvme_mi_mi_config_get_mctp_mtu - get configuration: MCTP MTU
 * @ep: endpoint for MI communication
 * @port: port ID to query
 * @mtu: output value for current MCTP MTU configuration
 *
 * Performs a MI Configuration Get, to query the current MCTP Maximum
 * Transmission Unit size (MTU) of the port specified in @port. On success,
 * populates @mtu with the MTU.
 *
 * The default reset value is 64, corresponding to the MCTP baseline MTU.
 *
 * Some controllers may also use this as the maximum receive unit size, and
 * may not accept MCTP messages larger than the configured MTU.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
static inline int libnvme_mi_mi_config_get_mctp_mtu(libnvme_mi_ep_t ep, __u8 port,
						 __u16 *mtu)
{
	__u32 tmp, dw0;
	int rc;

	dw0 = port << 24 | NVME_MI_CONFIG_MCTP_MTU;

	rc = libnvme_mi_mi_config_get(ep, dw0, 0, &tmp);
	if (!rc)
		*mtu = tmp & 0xffff;
	return rc;
}

/**
 * libnvme_mi_mi_config_set_mctp_mtu - set configuration: MCTP MTU
 * @ep: endpoint for MI communication
 * @port: port ID to set
 * @mtu: new MTU configuration
 *
 * Performs a MI Configuration Set, to update the current MCTP MTU value for
 * the port specified in @port.
 *
 * Some controllers may also use this as the maximum receive unit size, and
 * may not accept MCTP messages larger than the configured MTU. When setting
 * this value, you will likely need to change the MTU of the local MCTP
 * interface(s) to match.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
static inline int libnvme_mi_mi_config_set_mctp_mtu(libnvme_mi_ep_t ep, __u8 port,
						 __u16 mtu)
{
	__u32 dw0 = port << 24 | NVME_MI_CONFIG_MCTP_MTU;

	return libnvme_mi_mi_config_set(ep, dw0, mtu);
}


/**
 * libnvme_mi_mi_config_get_async_event - get configuration: Asynchronous Event
 * @ep: endpoint for MI communication
 * @aeelver: Asynchronous Event Enable List Version Number
 * @list: AE Supported list header and list contents
 * @list_num_bytes: number of bytes in the list header and contents buffer.
 * This will be populated with returned size of list and contents if successful.
 *
 * Performs a MI Configuration Get, to query the current enable Asynchronous
 * Events.  On success, populates @aeelver and the @list with current info,
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int libnvme_mi_mi_config_get_async_event(libnvme_mi_ep_t ep,
				__u8 *aeelver,
				struct nvme_mi_aem_supported_list *list,
				size_t *list_num_bytes);

/**
 * libnvme_mi_mi_config_set_async_event - set configuration: Asynchronous Event
 * @ep: endpoint for MI communication
 * @envfa: Enable SR-IOV Virtual Functions AE
 * @empfa: Enable SR-IOV Physical Functions AE
 * @encfa: Enable PCI Functions AE.
 * @aemd: AEM Delay Interval (for Sync only)
 * @aerd: AEM Retry Delay (for Sync only; time in 100s of ms)
 * @enable_list: libnvme_mi_aem_enable_listucture containing header and items
 * of events to be enabled or disabled.  This is taken as a delta change
 * from the current configuration.
 * @enable_list_size: Size of the enable_list including header and data.
 * Meant to catch overrun issues.
 * @occ_list: Pointer to populate with the occurrence list (header and data)
 * @occ_list_size: Total size of provided occ_list buffer.  Will be updated
 * with received size if successful
 *
 * Performs a MI Configuration Set, to ACK (sent after an AEM) or Sync (at anytime to enable
 * or disable Asynchronous Events).
 *
 * On success, populates @occ_list.  See TP6035a for details on how occ_list is populated in
 * ACK versus Sync conditions
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int libnvme_mi_mi_config_set_async_event(libnvme_mi_ep_t ep,
				bool envfa,
				bool empfa,
				bool encfa,
				__u8 aemd,
				__u8 aerd,
				struct nvme_mi_aem_enable_list *enable_list,
				size_t enable_list_size,
				struct nvme_mi_aem_occ_list_hdr *occ_list,
				size_t *occ_list_size);

static inline int libnvme_mi_aem_ack(libnvme_mi_ep_t ep,
				struct nvme_mi_aem_occ_list_hdr *occ_list,
				size_t *occ_list_size)
{
	//An AEM Ack is defined as a SET CONFIG AE with no AE enable items
	struct nvme_mi_aem_enable_list list = {0};

	list.hdr.aeelhl = sizeof(struct nvme_mi_aem_enable_list_header);
	list.hdr.aeelver = 0;
	list.hdr.aeetl = sizeof(struct nvme_mi_aem_enable_list_header);
	list.hdr.numaee = 0;

	return libnvme_mi_mi_config_set_async_event(ep, false, false, false, 0, 0,
						&list, sizeof(list), occ_list,
						occ_list_size);
}

/* Admin channel functions */

/**
 * libnvme_mi_admin_xfer() -  Raw admin transfer interface.
 * @hdl: transport handle to send the admin command to
 * @admin_req: request data
 * @req_data_size: size of request data payload
 * @admin_resp: buffer for response data
 * @resp_data_offset: offset into request data to retrieve from controller
 * @resp_data_size: size of response data buffer, updated to received size
 *
 * Performs an arbitrary NVMe Admin command, using the provided request data,
 * in @admin_req. The size of the request data *payload* is specified in
 * @req_data_size - this does not include the standard header length (so a
 * header-only request would have a size of 0).
 *
 * On success, response data is stored in @admin_resp, which has an optional
 * appended payload buffer of @resp_data_size bytes. The actual payload
 * transferred will be stored in @resp_data_size. These sizes do not include
 * the Admin request header, so 0 represents no payload.
 *
 * As with all Admin commands, we can request partial data from the Admin
 * Response payload, offset by @resp_data_offset.
 *
 * See: &struct nvme_mi_admin_req_hdr and &struct nvme_mi_admin_resp_hdr.
 *
 * Return: The nvme command status if a response was received (see
 * &enum nvme_status_field) or -1 with errno set otherwise..
 */
int libnvme_mi_admin_xfer(struct libnvme_transport_handle *hdl,
		       struct nvme_mi_admin_req_hdr *admin_req,
		       size_t req_data_size,
		       struct nvme_mi_admin_resp_hdr *admin_resp,
		       off_t resp_data_offset,
		       size_t *resp_data_size);

/**
 * libnvme_mi_control() - Perform a Control Primitive command
 * @ep: endpoint for MI communication
 * @opcode: Control Primitive opcode (using &enum nvme_mi_control_opcode)
 * @cpsp: Control Primitive Specific Parameter
 * @result_cpsr: Optional field to return the result from the CPSR field
 *
 * Perform a Control Primitive command, using the opcode specified in @opcode
 * Stores the result from the CPSR field in @result_cpsr if set.
 *
 * Return: 0 on success, non-zero on failure
 *
 * See: &enum nvme_mi_control_opcode
 *
 */
int libnvme_mi_control(libnvme_mi_ep_t ep, __u8 opcode,
		    __u16 cpsp, __u16 *result_cpsr);

/**
 * enum libnvme_mi_aem_handler_next_action - Next action for the AEM state machine handler
 * @NVME_MI_AEM_HNA_ACK: Send an ack for the AEM
 * @NVME_MI_AEM_HNA_NONE: No further action
 *
 * Used as return value for the AE callback generated when calling libnvme_mi_aem_process
 */
enum libnvme_mi_aem_handler_next_action {
	NVME_MI_AEM_HNA_ACK,
	NVME_MI_AEM_HNA_NONE,
};

/**
 * struct libnvme_mi_event - AE event information structure
 * @aeoi: Event identifier
 * @aessi: Event occurrence scope info
 * @aeocidi: Event occurrence scope ID info
 * @spec_info: Specific info buffer
 * @spec_info_len: Length of specific info buffer
 * @vend_spec_info: Vendor specific info buffer
 * @vend_spec_info_len: Length of vendor specific info buffer
 *
 * Application callbacks for libnvme_mi_aem_process will be able to call
 * libnvme_mi_aem_get_next_event which will return a pointer to such an identifier
 * for the next event the application should parse
 */
struct libnvme_mi_event {
	uint8_t aeoi;
	uint8_t aessi;
	uint32_t aeocidi;
	void *spec_info;
	size_t spec_info_len;
	void *vend_spec_info;
	size_t vend_spec_info_len;
};

/**
 * libnvme_mi_aem_get_next_event() - Get details for the next event to parse
 * @ep: The endpoint with the event
 *
 * When inside a aem_handler, call this and a returned struct pointer
 * will provide details of event information.  Will return NULL when end of parsing is occurred.
 * spec_info and vend_spec_info must be copied to persist as they will not be valid
 * after the handler_next_action has returned.
 *
 * Return: Pointer no next libnvme_mi_event or NULL if this is the last one
 */
struct libnvme_mi_event *libnvme_mi_aem_get_next_event(libnvme_mi_ep_t ep);

struct libnvme_mi_aem_enabled_map {
	bool enabled[256];
};

/**
 * struct libnvme_mi_aem_config - Provided for libnvme_mi_aem_enable
 * @aem_handler: Callback function for application processing of events
 * @enabled_map: Map indicating which AE should be enabled on the endpoint
 * @envfa: Enable SR-IOV virtual functions AE
 * @empfa: Enable SR-IOV physical functions AE
 * @encfa: Enable PCIe functions AE
 * @aemd: AEM Delay (time in seconds from when event happens to AEM being batched and sent)
 * @aerd: AEM Retry Delay (time in 100s of ms between AEM retries from the endpoint)
 *
 * Application callbacks for libnvme_mi_aem_process will be able to call
 * libnvme_mi_aem_get_next_event which will return a pointer to such an identifier
 * for the next event the application should parse
 */
struct libnvme_mi_aem_config {
	/*
	 * This is called from inside libnvme_mi_process when a payload has been validated and
	 * can be parsed.  The application may call libnvme_mi_aem_get_next_event from inside
	 *  the callback to parse event data.
	 */
	enum libnvme_mi_aem_handler_next_action (*aem_handler)(
							libnvme_mi_ep_t ep,
							size_t num_events,
							void *userdata);

	struct libnvme_mi_aem_enabled_map enabled_map;

	bool envfa;
	bool empfa;
	bool encfa;
	__u8 aemd;
	__u8 aerd;
};

/**
 * libnvme_mi_aem_get_fd() - Returns the pollable fd for AEM data available
 * @ep: The endpoint being monitored for asynchronous data
 *
 * This populated structure can be polled from the application to understand if
 * a call to libnvme_mi_aem_process() is required (when a poll returns > 0).
 *
 * Return: The fd value or -1 if error
 */
int libnvme_mi_aem_get_fd(libnvme_mi_ep_t ep);

/**
 * libnvme_mi_aem_enable() - Enable AE on the provided endpoint
 * @ep: Endpoint to enable AEs
 * @config: AE configuraiton including which events are enabled and the callback function
 * @userdata: Application provided context pointer for callback function
 *
 * This function is called to enable AE on the endpoint.  Endpoint will provide initial state
 * (if any) of enabled AEs and application can parse those via the aem_handler fn pointer in
 * callbacks.  Thes can be obtained in the callback by calling libnvme_mi_aem_get_next_event().
 *
 * Application should poll the fd that can be obtained from libnvme_mi_aem_get_fd and then call
 * libnvme_mi_aem_process() when poll() indicates data available.
 *
 * A call to libnvme_mi_aem_process() will grab AEM data and call the aem_handler fn pointer.
 * At this point the application can call libnvme_mi_aem_get_next_event() to get information for
 * each triggered event.
 *
 * Return: 0 is a success, nonzero is an error and errno may be read for further details
 */
int libnvme_mi_aem_enable(libnvme_mi_ep_t ep,
	struct libnvme_mi_aem_config *config,
	void *userdata);


/**
 * libnvme_mi_aem_get_enabled() - Return information on which AEs are enabled
 * @ep: Endpoint to check enabled status
 * @enabled: libnvme_mi_aem_enabled_map indexed by AE event ID of enabled state
 *
 * Return: 0 is a success, nonzero is an error and errno may be read for further details
 */
int libnvme_mi_aem_get_enabled(libnvme_mi_ep_t ep,
	struct libnvme_mi_aem_enabled_map *enabled);

/**
 * libnvme_mi_aem_disable() - Disable AE on the provided endpoint
 * @ep: Endpoint to disable AEs
 *
 * Return: 0 is a success, nonzero is an error and errno may be read for further details
 */
int libnvme_mi_aem_disable(libnvme_mi_ep_t ep);

/**
 * libnvme_mi_aem_process() - Process AEM on the provided endpoint
 * @ep: Endpoint to process
 * @userdata: Application provided context pointer for callback function
 *
 * Call this if poll() indicates data is available on the fd provided by libnvme_mi_aem_get_fd()
 *
 * This will call the fn pointer, aem_handler, provided with libnvme_mi_aem_config and the
 * application can call libnvme_mi_aem_get_next_event() from within this callback to get
 * aem event data.  The callback function should return NVME_MI_AEM_HNA_ACK for normal operation.
 *
 * Return: 0 is a success, nonzero is an error and errno may be read for further details
 */
int libnvme_mi_aem_process(libnvme_mi_ep_t ep, void *userdata);

/**
 * libnvme_mi_submit_entry() - Weak hook called before an MI message is sent.
 * @type:	MCTP message type
 * @hdr:	Pointer to the MI message header
 * @hdr_len:	Length of the message header in bytes
 * @data:	Pointer to message payload data
 * @data_len:	Length of payload data in bytes
 *
 * This is a weak symbol that can be overridden by an application to intercept
 * outgoing MI messages for tracing or testing purposes.  The return value is
 * passed back as @user_data to the matching libnvme_mi_submit_exit() call.
 *
 * Return: An opaque pointer passed to libnvme_mi_submit_exit(), or NULL.
 */
void *libnvme_mi_submit_entry(__u8 type, const struct nvme_mi_msg_hdr *hdr,
			      size_t hdr_len, const void *data, size_t data_len);

/**
 * libnvme_mi_submit_exit() - Weak hook called after an MI message completes.
 * @type:	MCTP message type
 * @hdr:	Pointer to the MI response message header
 * @hdr_len:	Length of the response message header in bytes
 * @data:	Pointer to response payload data
 * @data_len:	Length of response payload data in bytes
 * @user_data:	Value returned by the matching libnvme_mi_submit_entry() call
 *
 * This is a weak symbol that can be overridden by an application to intercept
 * completed MI transactions.  Called with the opaque pointer returned by the
 * corresponding libnvme_mi_submit_entry() call.
 */
void libnvme_mi_submit_exit(__u8 type, const struct nvme_mi_msg_hdr *hdr,
			    size_t hdr_len, const void *data, size_t data_len,
			    void *user_data);
