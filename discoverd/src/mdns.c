// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <martin.belanger@dell.com>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <ccan/array_size/array_size.h>
#include <ccan/list/list.h>
#include <ccan/str/str.h>
#include <shared/time-util.h>
#include <systemd/sd-json.h>
#include <systemd/sd-varlink.h>

#include "log.h"
#include "mdns.h"
#include "netif.h"

#define RESOLVE_VARLINK_ADDRESS "/run/systemd/resolve/io.systemd.Resolve"
#define RESOLVE_INTERFACE       "io.systemd.Resolve"
#define VARLINK_GET_DESCRIPTION "org.varlink.service.GetInterfaceDescription"
#define VARLINK_BROWSE_SERVICES "io.systemd.Resolve.BrowseServices"
#define VARLINK_RESOLVE_SERVICE "io.systemd.Resolve.ResolveService"

/*
 * NVMe Base Spec 2.4 §8.3.1.1.1, Figure 800 (TP8009): TCP and iWARP DCs
 * advertise "_tcp", RoCE DCs advertise "_udp". Each type needs its own
 * BrowseServices call.
 */
static const char * const mdns_service_types[] = {
	"_nvme-disc._tcp",
	"_nvme-disc._udp",
};

/*
 * Retry intervals, in seconds, for the TCP reachability check. Some DCs
 * advertise before their TCP listener is up. An NVMe connect through the
 * kernel fails at that point, and the nvme driver logs errors. A plain
 * TCP connect from userspace fails silently. So a tcp endpoint is
 * reported only after a userspace TCP connect to it succeeds. The last
 * interval repeats: the check stops only when the advertisement is
 * withdrawn.
 */
static const unsigned int tcp_check_retry_sec[] = {
	2, 5, 10, 30, 60, 300, 600,
};

/*
 * Restart delay, in seconds, after a browse call fails, e.g. because
 * systemd-resolved restarted. Doubles on each failed attempt, up to the
 * maximum.
 */
#define BROWSE_RESTART_MIN_SEC	1
#define BROWSE_RESTART_MAX_SEC	60

/* One resolved connect endpoint for a discovered mDNS service instance. */
struct mdns_endpoint {
	struct list_node entry;
	char *traddr;
	char *trsvcid;
};

/* A TCP reachability check for a tcp endpoint not yet reported. */
struct tcp_check {
	struct list_node entry;
	struct mdns_browse *br;
	struct mdns_service *svc;
	char *traddr;
	char *trsvcid;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int fd; // -1 when not connecting
	sd_event_source *io_source;
	sd_event_source *retry_timer;
	size_t retry_idx; // into tcp_check_retry_sec[]
	bool ceiling_logged; // for disc_info_once()
};

/* One discovered mDNS service instance, keyed by name within its browse. */
struct mdns_service {
	struct list_node entry;
	char *name;
	const char *transport; // "tcp" or "rdma", from the TXT record's p= key
	char *nqn; // TXT record's optional nqn= key, NULL if absent
	struct list_head endpoints;
	struct list_head checks; // struct tcp_check
};

/* One outstanding ResolveService call for a just-added service instance. */
struct resolve_req {
	struct list_node entry;
	struct mdns_browse *br;
	sd_varlink *link;
	char *name;
};

/* One per-interface BrowseServices subscription. */
struct mdns_browse {
	struct list_node entry;
	struct mdns_ctx *mctx;
	int ifindex;
	char *ifname;
	const char *type; // one of mdns_service_types[], static duration
	sd_varlink *link; // NULL while waiting to restart
	sd_event_source *restart_timer;
	unsigned int restart_sec; // next restart delay
	struct list_head services; // struct mdns_service, resolved instances
	struct list_head pending;  // struct resolve_req, in-flight resolves
};

struct mdns_ctx {
	sd_event *event;
	struct mdns_callbacks callbacks;
	void *user_data;
	struct netif_ctx *nctx;
	struct list_head browses; // struct mdns_browse, one per candidate iface
};

/* @v's "key" member as a string, or NULL if absent or not a string. */
static const char *json_str(sd_json_variant *v, const char *key)
{
	v = sd_json_variant_by_key(v, key);

	return v ? sd_json_variant_string(v) : NULL;
}

/* @v's "key" member, or NULL if absent or not an array. */
static sd_json_variant *json_array(sd_json_variant *v, const char *key)
{
	v = sd_json_variant_by_key(v, key);

	return v && sd_json_variant_is_array(v) ? v : NULL;
}

/*
 * Returns 0 if io.systemd.Resolve has a BrowseServices method, -EOPNOTSUPP
 * if not, or another negative errno.
 */
static int resolved_has_browse_services(sd_varlink *link)
{
	sd_json_variant *reply = NULL;
	const char *error_id = NULL;
	const char *text;
	int r;

	r = sd_varlink_callbo(link, VARLINK_GET_DESCRIPTION, &reply, &error_id,
			      SD_JSON_BUILD_PAIR_STRING("interface",
							RESOLVE_INTERFACE));
	if (r < 0)
		return r;
	if (error_id)
		return -EPROTO;

	text = json_str(reply, "description");
	if (!text || !strstr(text, "method BrowseServices("))
		return -EOPNOTSUPP;

	return 0;
}

static void mdns_endpoint_free(struct mdns_endpoint *ep)
{
	if (!ep)
		return;
	list_del_init(&ep->entry);
	free(ep->traddr);
	free(ep->trsvcid);
	free(ep);
}

static void tcp_check_free(struct tcp_check *tc)
{
	if (!tc)
		return;
	list_del_init(&tc->entry);
	sd_event_source_unref(tc->io_source);
	sd_event_source_unref(tc->retry_timer);
	if (tc->fd >= 0)
		close(tc->fd);
	free(tc->traddr);
	free(tc->trsvcid);
	free(tc);
}

static struct mdns_service *service_find(struct mdns_browse *br,
					  const char *name)
{
	struct mdns_service *svc;

	list_for_each(&br->services, svc, entry) {
		if (streq(svc->name, name))
			return svc;
	}
	return NULL;
}

/* Cancel the checks, report every endpoint as removed, then free @svc. */
static void service_free(struct mdns_browse *br, struct mdns_service *svc)
{
	struct mdns_endpoint *ep, *next;
	struct tcp_check *tc, *next_tc;

	list_for_each_safe(&svc->checks, tc, next_tc, entry)
		tcp_check_free(tc);

	list_for_each_safe(&svc->endpoints, ep, next, entry) {
		if (br->mctx->callbacks.service_remove)
			br->mctx->callbacks.service_remove(
				ep->traddr, ep->trsvcid, svc->transport,
				svc->nqn, br->ifname, br->ifindex,
				br->mctx->user_data);
		mdns_endpoint_free(ep);
	}

	list_del_init(&svc->entry);
	free(svc->name);
	free(svc->nqn);
	free(svc);
}

/*
 * NVMe Base Spec 2.4 §8.3.1.1.2 (TP8009): the TXT record's p= key gives the
 * transport. The service type cannot: iWARP is RDMA but advertises "_tcp".
 * Matched case-insensitively.
 */
static const char *proto_to_transport(const char *proto)
{
	if (!strcasecmp(proto, "tcp"))
		return "tcp";
	if (!strcasecmp(proto, "roce") || !strcasecmp(proto, "iwarp") ||
	    !strcasecmp(proto, "rdma"))
		return "rdma";

	return NULL;
}

/*
 * Read the TXT record's p= and nqn= keys. Returns -EINVAL if p= is missing
 * or unknown. *ret_nqn is borrowed from @parameters, or NULL.
 */
static int resolve_txt(sd_json_variant *parameters,
		       const char **ret_transport, const char **ret_nqn)
{
	sd_json_variant *txt, *item;
	size_t i, n;

	*ret_transport = NULL;
	*ret_nqn = NULL;

	txt = json_array(parameters, "txt");
	if (!txt)
		return -EINVAL;

	n = sd_json_variant_elements(txt);
	for (i = 0; i < n; i++) {
		const char *kv;

		item = sd_json_variant_by_index(txt, i);
		kv = sd_json_variant_string(item);
		if (!kv)
			continue;

		if (!*ret_transport && !strncmp(kv, "p=", 2))
			*ret_transport = proto_to_transport(kv + 2);
		else if (!*ret_nqn && !strncmp(kv, "nqn=", 4))
			*ret_nqn = kv + 4;
	}

	return *ret_transport ? 0 : -EINVAL;
}

/* Link @traddr/@trsvcid (ownership taken) into @svc and report it. */
static void report_endpoint(struct mdns_browse *br, struct mdns_service *svc,
			    char *traddr, char *trsvcid)
{
	struct mdns_endpoint *ep;

	if (!traddr || !trsvcid) {
		free(traddr);
		free(trsvcid);
		return;
	}

	ep = calloc(1, sizeof(*ep));
	if (!ep) {
		free(traddr);
		free(trsvcid);
		return;
	}
	list_node_init(&ep->entry); // safe to free unlinked
	ep->traddr = traddr;
	ep->trsvcid = trsvcid;
	list_add(&svc->endpoints, &ep->entry);

	if (br->mctx->callbacks.service_add)
		br->mctx->callbacks.service_add(ep->traddr, ep->trsvcid,
						svc->transport, svc->nqn,
						br->ifname, br->ifindex,
						br->mctx->user_data);
}

static void tcp_check_start(struct tcp_check *tc);

static int tcp_check_retry_cback(sd_event_source *s __attribute__((unused)),
				 uint64_t usec __attribute__((unused)),
				 void *userdata)
{
	struct tcp_check *tc = userdata;

	tc->retry_timer = sd_event_source_unref(tc->retry_timer);
	tcp_check_start(tc);

	return 0;
}

/* Close the current attempt, if any, and arm the next retry. */
static void tcp_check_schedule_retry(struct tcp_check *tc)
{
	size_t last = ARRAY_SIZE(tcp_check_retry_sec) - 1;
	unsigned int sec;
	uint64_t now;
	int r;

	tc->io_source = sd_event_source_unref(tc->io_source);
	if (tc->fd >= 0) {
		close(tc->fd);
		tc->fd = -1;
	}

	sec = tcp_check_retry_sec[tc->retry_idx];
	if (tc->retry_idx < last)
		tc->retry_idx++;
	else
		disc_info_once(&tc->ceiling_logged,
			       "mdns: %s: %s:%s still unreachable, retrying every %us",
			       tc->br->ifname, tc->traddr, tc->trsvcid, sec);

	r = sd_event_now(tc->br->mctx->event, CLOCK_BOOTTIME, &now);
	if (r >= 0)
		r = sd_event_add_time(tc->br->mctx->event, &tc->retry_timer,
				      CLOCK_BOOTTIME,
				      now + sec * UINT64_C(1000000), 0,
				      tcp_check_retry_cback, tc);
	if (r < 0)
		disc_err("mdns: %s: %s:%s: cannot arm retry timer: %s",
			 tc->br->ifname, tc->traddr, tc->trsvcid,
			 strerror(-r));
}

/* Reachable: report the endpoint and free @tc. */
static void tcp_check_succeeded(struct tcp_check *tc)
{
	char *traddr = tc->traddr;
	char *trsvcid = tc->trsvcid;

	tc->traddr = NULL;
	tc->trsvcid = NULL;
	report_endpoint(tc->br, tc->svc, traddr, trsvcid);
	tcp_check_free(tc);
}

static int tcp_check_io_cback(sd_event_source *s __attribute__((unused)),
			      int fd,
			      uint32_t revents __attribute__((unused)),
			      void *userdata)
{
	struct tcp_check *tc = userdata;
	socklen_t len = sizeof(int);
	int err = 0;

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err) {
		tcp_check_schedule_retry(tc);
		return 0;
	}

	tcp_check_succeeded(tc);

	return 0;
}

static void tcp_check_start(struct tcp_check *tc)
{
	int r;

	tc->fd = socket(tc->addr.ss_family,
			SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
			IPPROTO_TCP);
	if (tc->fd < 0) {
		tcp_check_schedule_retry(tc);
		return;
	}

	r = connect(tc->fd, (struct sockaddr *)&tc->addr, tc->addrlen);
	if (r < 0 && errno != EINPROGRESS) {
		tcp_check_schedule_retry(tc);
		return;
	}

	r = sd_event_add_io(tc->br->mctx->event, &tc->io_source, tc->fd,
			    EPOLLOUT, tcp_check_io_cback, tc);
	if (r < 0)
		tcp_check_schedule_retry(tc);
}

/*
 * Start a reachability check for a tcp endpoint. Takes ownership of
 * @traddr and @trsvcid.
 */
static void tcp_check_new(struct mdns_browse *br, struct mdns_service *svc,
			  char *traddr, char *trsvcid,
			  const struct sockaddr_storage *ss, socklen_t sslen)
{
	struct tcp_check *tc;

	if (!traddr || !trsvcid)
		goto err;

	tc = calloc(1, sizeof(*tc));
	if (!tc)
		goto err;
	tc->br = br;
	tc->svc = svc;
	tc->traddr = traddr;
	tc->trsvcid = trsvcid;
	tc->addr = *ss;
	tc->addrlen = sslen;
	tc->fd = -1;
	list_add(&svc->checks, &tc->entry);

	tcp_check_start(tc);
	return;
err:
	free(traddr);
	free(trsvcid);
}

/* Build the sockaddr for a tcp endpoint. Returns its length. */
static socklen_t endpoint_sockaddr(int family, const void *addr, int port,
				   int ifindex, struct sockaddr_storage *ss)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;

	memset(ss, 0, sizeof(*ss));

	if (family == AF_INET) {
		sin->sin_family = AF_INET;
		sin->sin_port = htons((uint16_t)port);
		memcpy(&sin->sin_addr, addr, sizeof(sin->sin_addr));

		return sizeof(*sin);
	}

	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = htons((uint16_t)port);
	memcpy(&sin6->sin6_addr, addr, sizeof(sin6->sin6_addr));
	if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
		sin6->sin6_scope_id = ifindex;

	return sizeof(*sin6);
}

/* Parse one ResolveService "services[]" entry's port and addresses. */
static void add_endpoints(struct mdns_browse *br, struct mdns_service *svc,
			  sd_json_variant *service_item)
{
	sd_json_variant *port_v, *addrs, *addr_item, *family_v, *bytes_v, *b;
	char *trsvcid;
	size_t i, n;
	int port;

	port_v = sd_json_variant_by_key(service_item, "port");
	if (!port_v)
		return;

	addrs = json_array(service_item, "addresses");
	if (!addrs)
		return;

	port = (int)sd_json_variant_integer(port_v);
	if (port < 1 || port > 65535) {
		disc_warn("mdns: %s: '%s': bad port %d, ignoring",
			 br->ifname, svc->name, port);
		return;
	}

	if (asprintf(&trsvcid, "%d", port) < 0)
		return;

	n = sd_json_variant_elements(addrs);
	for (i = 0; i < n; i++) {
		union {
			struct in_addr in4;
			struct in6_addr in6;
		} a;
		char buf[INET6_ADDRSTRLEN];
		unsigned char *p;
		int family;
		size_t j, nbytes;

		addr_item = sd_json_variant_by_index(addrs, i);
		family_v = sd_json_variant_by_key(addr_item, "family");
		if (!family_v)
			continue;

		bytes_v = json_array(addr_item, "address");
		if (!bytes_v)
			continue;

		family = (int)sd_json_variant_integer(family_v);
		nbytes = sd_json_variant_elements(bytes_v);
		if (family == AF_INET && nbytes == sizeof(a.in4))
			p = (unsigned char *)&a.in4;
		else if (family == AF_INET6 && nbytes == sizeof(a.in6))
			p = (unsigned char *)&a.in6;
		else
			continue;

		for (j = 0; j < nbytes; j++) {
			b = sd_json_variant_by_index(bytes_v, j);
			p[j] = (unsigned char)sd_json_variant_integer(b);
		}
		if (!inet_ntop(family, &a, buf, sizeof(buf)))
			continue;

		if (streq(svc->transport, "tcp")) {
			struct sockaddr_storage ss;
			socklen_t sslen;

			sslen = endpoint_sockaddr(family, &a, port, br->ifindex,
						  &ss);
			tcp_check_new(br, svc, strdup(buf), strdup(trsvcid),
				      &ss, sslen);
		} else {
			report_endpoint(br, svc, strdup(buf), strdup(trsvcid));
		}
	}

	free(trsvcid);
}

static void resolve_req_free(struct resolve_req *req)
{
	if (!req)
		return;
	list_del_init(&req->entry);
	sd_varlink_flush_close_unref(req->link);
	free(req->name);
	free(req);
}

static int resolve_reply_cb(sd_varlink *link __attribute__((unused)),
			    sd_json_variant *parameters, const char *error_id,
			    sd_varlink_reply_flags_t flags
				    __attribute__((unused)),
			    void *userdata)
{
	struct resolve_req *req = userdata;
	struct mdns_browse *br = req->br;
	sd_json_variant *services;
	struct mdns_service *svc;
	const char *transport, *nqn;
	size_t i, n;

	if (error_id) {
		disc_warn("mdns: %s: resolve '%s': %s", br->ifname, req->name,
			 error_id);
		goto out;
	}

	services = json_array(parameters, "services");
	if (!services)
		goto out;

	if (resolve_txt(parameters, &transport, &nqn) < 0) {
		disc_warn("mdns: %s: resolve '%s': missing/invalid transport in TXT record",
			 br->ifname, req->name);
		goto out;
	}

	svc = calloc(1, sizeof(*svc));
	if (!svc)
		goto out;
	list_node_init(&svc->entry); // safe to free even if never list_add()'d
	list_head_init(&svc->endpoints);
	list_head_init(&svc->checks);
	svc->name = req->name;
	svc->transport = transport;
	svc->nqn = nqn ? strdup(nqn) : NULL;
	req->name = NULL;

	n = sd_json_variant_elements(services);
	for (i = 0; i < n; i++)
		add_endpoints(br, svc, sd_json_variant_by_index(services, i));

	if (list_empty(&svc->endpoints) && list_empty(&svc->checks))
		service_free(br, svc); // nothing resolved
	else
		list_add(&br->services, &svc->entry);

out:
	resolve_req_free(req);
	return 0;
}

static void resolve_service(struct mdns_browse *br, const char *name,
			    const char *type, const char *domain)
{
	struct resolve_req *req;
	int r;

	req = calloc(1, sizeof(*req));
	if (!req)
		return;
	req->br = br;
	req->name = strdup(name);
	if (!req->name)
		goto err_req;

	r = sd_varlink_connect_address(&req->link, RESOLVE_VARLINK_ADDRESS);
	if (r < 0) {
		disc_warn("mdns: %s: resolve '%s': connect: %s", br->ifname,
			 name, strerror(-r));
		goto err_name;
	}

	r = sd_varlink_attach_event(req->link, br->mctx->event,
				    SD_EVENT_PRIORITY_NORMAL);
	if (r < 0)
		goto err_link;

	sd_varlink_set_userdata(req->link, req);
	r = sd_varlink_bind_reply(req->link, resolve_reply_cb);
	if (r < 0)
		goto err_link;

	r = sd_varlink_invokebo(req->link, VARLINK_RESOLVE_SERVICE,
			       SD_JSON_BUILD_PAIR_STRING("name", name),
			       SD_JSON_BUILD_PAIR_STRING("type", type),
			       SD_JSON_BUILD_PAIR_STRING("domain", domain),
			       SD_JSON_BUILD_PAIR_INTEGER("ifindex",
							  br->ifindex));
	if (r < 0)
		goto err_link;

	list_add(&br->pending, &req->entry);
	return;

err_link:
	sd_varlink_flush_close_unref(req->link);
err_name:
	free(req->name);
err_req:
	free(req);
}

/* Is a ResolveService for @name already in flight on @br? */
static bool resolve_pending(struct mdns_browse *br, const char *name)
{
	struct resolve_req *req;

	list_for_each(&br->pending, req, entry) {
		if (req->name && streq(req->name, name))
			return true;
	}
	return false;
}

static void service_added(struct mdns_browse *br, const char *name,
			  const char *type, const char *domain)
{
	/*
	 * A service joins br->services only when its resolve replies. Check
	 * the pending resolves too, or a repeated announcement starts a
	 * second resolve for the same name.
	 */
	if (service_find(br, name) || resolve_pending(br, name))
		return;

	resolve_service(br, name, type, domain);
}

static void service_removed(struct mdns_browse *br, const char *name)
{
	struct mdns_service *svc = service_find(br, name);

	if (svc)
		service_free(br, svc);
}

static void handle_service_data(struct mdns_browse *br, sd_json_variant *item)
{
	const char *update = json_str(item, "updateFlag");
	const char *name = json_str(item, "name");
	const char *type = json_str(item, "type");
	const char *domain = json_str(item, "domain");

	if (!update || !name)
		return;

	if (streq(update, "added") && type && domain)
		service_added(br, name, type, domain);
	else if (streq(update, "removed"))
		service_removed(br, name);
}

static void browse_schedule_restart(struct mdns_browse *br);

/*
 * Close the browse call. Every service found through it is reported as
 * removed. It is found again when the browse restarts.
 */
static void browse_disconnect(struct mdns_browse *br)
{
	struct mdns_service *svc, *next_svc;
	struct resolve_req *req, *next_req;

	list_for_each_safe(&br->pending, req, next_req, entry)
		resolve_req_free(req);

	list_for_each_safe(&br->services, svc, next_svc, entry)
		service_free(br, svc);

	br->link = sd_varlink_flush_close_unref(br->link);
}

static int browse_reply_cb(sd_varlink *link __attribute__((unused)),
			   sd_json_variant *parameters, const char *error_id,
			   sd_varlink_reply_flags_t flags, void *userdata)
{
	struct mdns_browse *br = userdata;
	sd_json_variant *arr;
	size_t i, n;

	if (error_id) {
		disc_warn("mdns: %s: browsing %s failed: %s, restarting",
			  br->ifname, br->type, error_id);
		goto restart;
	}

	arr = json_array(parameters, "browserServiceData");
	if (!arr)
		disc_warn("mdns: %s: BrowseServices reply without browserServiceData",
			  br->ifname);
	n = arr ? sd_json_variant_elements(arr) : 0;
	for (i = 0; i < n; i++)
		handle_service_data(br, sd_json_variant_by_index(arr, i));

	if (flags & SD_VARLINK_REPLY_CONTINUES)
		return 0;

	disc_warn("mdns: %s: browsing %s ended, restarting", br->ifname,
		  br->type);
restart:
	browse_disconnect(br);
	browse_schedule_restart(br);

	return 0;
}

/* Open a link to systemd-resolved and start the BrowseServices call. */
static int browse_connect(struct mdns_browse *br)
{
	int r;

	r = sd_varlink_connect_address(&br->link, RESOLVE_VARLINK_ADDRESS);
	if (r < 0)
		return r;

	/*
	 * The default 45 s timeout also applies to an observe call, counted
	 * from when it was sent. Browsing must run until stopped.
	 */
	r = sd_varlink_set_relative_timeout(br->link, SHR_USEC_INFINITY);
	if (r < 0)
		goto err;

	r = sd_varlink_attach_event(br->link, br->mctx->event,
				    SD_EVENT_PRIORITY_NORMAL);
	if (r < 0)
		goto err;

	sd_varlink_set_userdata(br->link, br);
	r = sd_varlink_bind_reply(br->link, browse_reply_cb);
	if (r < 0)
		goto err;

	r = sd_varlink_observebo(br->link, VARLINK_BROWSE_SERVICES,
				 SD_JSON_BUILD_PAIR_STRING("type", br->type),
				 SD_JSON_BUILD_PAIR_INTEGER("ifindex",
							    br->ifindex));
	if (r < 0)
		goto err;

	return 0;
err:
	br->link = sd_varlink_flush_close_unref(br->link);

	return r;
}

static int browse_restart_cback(sd_event_source *s __attribute__((unused)),
				uint64_t usec __attribute__((unused)),
				void *userdata)
{
	struct mdns_browse *br = userdata;
	int r;

	br->restart_timer = sd_event_source_unref(br->restart_timer);

	r = browse_connect(br);
	if (r < 0) {
		disc_dbg("mdns: %s: browsing %s: %s", br->ifname, br->type,
			 strerror(-r));
		browse_schedule_restart(br);
		return 0;
	}

	br->restart_sec = BROWSE_RESTART_MIN_SEC;
	disc_info("mdns: browsing %s for %s again", br->ifname, br->type);

	return 0;
}

static void browse_schedule_restart(struct mdns_browse *br)
{
	uint64_t now;
	int r;

	r = sd_event_now(br->mctx->event, CLOCK_BOOTTIME, &now);
	if (r >= 0)
		r = sd_event_add_time(br->mctx->event, &br->restart_timer,
				      CLOCK_BOOTTIME,
				      now + br->restart_sec * UINT64_C(1000000),
				      0, browse_restart_cback, br);
	if (r < 0) {
		disc_err("mdns: %s: browsing %s: cannot arm restart timer: %s",
			 br->ifname, br->type, strerror(-r));
		return;
	}

	br->restart_sec *= 2;
	if (br->restart_sec > BROWSE_RESTART_MAX_SEC)
		br->restart_sec = BROWSE_RESTART_MAX_SEC;
}

static struct mdns_browse *browse_find(struct mdns_ctx *mctx, int ifindex,
				       const char *type)
{
	struct mdns_browse *br;

	list_for_each(&mctx->browses, br, entry) {
		if (br->ifindex == ifindex && streq(br->type, type))
			return br;
	}
	return NULL;
}

static void browse_free(struct mdns_browse *br)
{
	if (!br)
		return;

	browse_disconnect(br);
	sd_event_source_unref(br->restart_timer);
	list_del_init(&br->entry);
	free(br->ifname);
	free(br);
}

/*
 * Start browsing @ifname for @type. If systemd-resolved is not reachable,
 * the browse is retried later.
 */
static void browse_start(struct mdns_ctx *mctx, int ifindex,
			 const char *ifname, const char *type)
{
	struct mdns_browse *br;
	int r;

	br = calloc(1, sizeof(*br));
	if (!br)
		return;
	list_node_init(&br->entry); // safe to free even if never list_add()'d
	list_head_init(&br->services);
	list_head_init(&br->pending);
	br->mctx = mctx;
	br->ifindex = ifindex;
	br->type = type;
	br->restart_sec = BROWSE_RESTART_MIN_SEC;
	br->ifname = strdup(ifname);
	if (!br->ifname) {
		browse_free(br);
		return;
	}
	list_add(&mctx->browses, &br->entry);

	r = browse_connect(br);
	if (r < 0) {
		disc_warn("mdns: %s: browsing %s: %s, retrying", ifname, type,
			  strerror(-r));
		browse_schedule_restart(br);
		return;
	}

	disc_info("mdns: browsing %s for %s", ifname, type);
}

static void on_iface_add(int ifindex, const char *ifname, void *user_data)
{
	struct mdns_ctx *mctx = user_data;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(mdns_service_types); i++) {
		const char *type = mdns_service_types[i];

		if (!browse_find(mctx, ifindex, type))
			browse_start(mctx, ifindex, ifname, type);
	}
}

static void on_iface_remove(int ifindex,
			    const char *ifname __attribute__((unused)),
			    void *user_data)
{
	struct mdns_ctx *mctx = user_data;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(mdns_service_types); i++) {
		struct mdns_browse *br =
			browse_find(mctx, ifindex, mdns_service_types[i]);

		if (br)
			browse_free(br);
	}
}

int mdns_start(sd_event *event, const struct mdns_callbacks *callbacks,
	       void *user_data, struct mdns_ctx **mctxp)
{
	static const struct netif_callbacks netif_cbs = {
		.iface_add    = on_iface_add,
		.iface_remove = on_iface_remove,
	};
	struct mdns_ctx *mctx;
	sd_varlink *probe;
	int r;

	r = sd_varlink_connect_address(&probe, RESOLVE_VARLINK_ADDRESS);
	if (r < 0)
		return r;

	r = resolved_has_browse_services(probe);
	sd_varlink_flush_close_unref(probe);
	if (r < 0)
		return r;

	mctx = calloc(1, sizeof(*mctx));
	if (!mctx)
		return -ENOMEM;
	mctx->event = event;
	mctx->callbacks = *callbacks;
	mctx->user_data = user_data;
	list_head_init(&mctx->browses);

	r = netif_start(event, &netif_cbs, mctx, &mctx->nctx);
	if (r < 0) {
		mdns_stop(mctx);
		return r;
	}

	*mctxp = mctx;

	return 0;
}

void mdns_stop(struct mdns_ctx *mctx)
{
	struct mdns_browse *br, *next;

	if (!mctx)
		return;

	netif_stop(mctx->nctx);

	list_for_each_safe(&mctx->browses, br, next, entry)
		browse_free(br);

	free(mctx);
}
