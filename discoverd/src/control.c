// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE LLC
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <ccan/array_size/array_size.h>
#include <ccan/list/list.h>
#include <ccan/str/str.h>

#include <daemon-util/log.h>
#include <shared/cleanup-util.h>
#include <shared/string-util.h>

#include "control.h"

#define MAX_LINE		4096
#define MAX_PROPS		32
#define SYNC_RECHECK_USEC	1000

struct control {
	sd_event *event;
	int fd;
	char *path;
	sd_event_source *listen_src;
	struct control_callbacks callbacks;
	void *user_data;
	struct list_head clients;
};

struct client {
	struct list_node node;
	struct control *c;
	int fd;
	sd_event_source *io;
	sd_event_source *sync_timer; // set while a "sync" waits
	char buf[MAX_LINE];
	size_t len;
	char *out; // replies not sent yet
	size_t out_len;
	bool dead; // to be freed once its callback returns
};

/* The KEY=VALUE properties of an injected uevent. */
struct props {
	char *key[MAX_PROPS];
	char *val[MAX_PROPS];
	int n;
};

static const char *props_get(const struct uevent *ev, const char *key)
{
	const struct props *p = ev->data;
	int i;

	for (i = 0; i < p->n; i++)
		if (streq(p->key[i], key))
			return p->val[i];

	return NULL;
}

static void client_free(struct client *cl)
{
	list_del(&cl->node);
	sd_event_source_disable_unref(cl->io);
	sd_event_source_disable_unref(cl->sync_timer);
	close(cl->fd);
	free(cl->out);
	free(cl);
}

/*
 * Send what the client has not got yet, as much as the socket takes. A
 * client that went away must not take the daemon down with SIGPIPE.
 */
static void flush(struct client *cl)
{
	size_t sent = 0;
	ssize_t n;

	while (sent < cl->out_len) {
		n = send(cl->fd, cl->out + sent, cl->out_len - sent,
			 MSG_NOSIGNAL);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && errno == EAGAIN)
			break;
		if (n <= 0) {
			log_warn("control: write failed: %s",
				 n < 0 ? strerror(errno) : "no progress");
			cl->dead = true;
			break;
		}
		sent += n;
	}

	memmove(cl->out, cl->out + sent, cl->out_len - sent);
	cl->out_len -= sent;
}

/*
 * Queue the reply @line. The socket is nonblocking: a client that does not
 * read its replies cannot block the event loop.
 */
static void reply(struct client *cl, const char *line)
{
	size_t len = strlen(line);
	char *out;

	if (cl->dead)
		return;

	out = realloc(cl->out, cl->out_len + len + 1);
	if (!out) {
		log_warn("control: out of memory");
		cl->dead = true;
		return;
	}
	memcpy(out + cl->out_len, line, len);
	out[cl->out_len + len] = '\n';
	cl->out = out;
	cl->out_len += len + 1;

	flush(cl);
}

/*
 * Read requests unless a sync waits or replies are pending, and wait for
 * the socket to take more while they are.
 */
static void update_events(struct client *cl)
{
	uint32_t events = 0;

	if (!cl->sync_timer && !cl->out_len)
		events |= EPOLLIN;
	if (cl->out_len)
		events |= EPOLLOUT;

	if (!events) {
		sd_event_source_set_enabled(cl->io, SD_EVENT_OFF);
		return;
	}
	sd_event_source_set_io_events(cl->io, events);
	sd_event_source_set_enabled(cl->io, SD_EVENT_ON);
}

static void handle_uevent(struct client *cl, char **tok, int n)
{
	struct props props = { };
	struct uevent ev = {
		.property = props_get,
		.data = &props,
	};
	int i;

	if (n < 4) {
		reply(cl, "error uevent needs SUBSYSTEM ACTION DEVNAME");
		return;
	}

	ev.subsystem = tok[1];
	ev.action = tok[2];
	ev.devname = streq(tok[3], "-") ? NULL : tok[3];

	for (i = 4; i < n; i++) {
		char *eq = strchr(tok[i], '=');

		if (!eq || eq == tok[i] || props.n == MAX_PROPS) {
			reply(cl, "error bad property");
			return;
		}
		*eq = '\0';
		props.key[props.n] = tok[i];
		props.val[props.n] = eq + 1;
		props.n++;
	}

	if (cl->c->callbacks.uevent)
		cl->c->callbacks.uevent(&ev, cl->c->user_data);
	reply(cl, "ok");
}

static void handle_dump(struct client *cl)
{
	__cleanup_free char *json = NULL;
	size_t size = 0;
	FILE *f;

	f = open_memstream(&json, &size);
	if (!f) {
		reply(cl, "error out of memory");
		return;
	}
	if (cl->c->callbacks.dump)
		cl->c->callbacks.dump(f, cl->c->user_data);
	else
		fputs("{}", f);
	if (fclose(f)) {
		reply(cl, "error out of memory");
		return;
	}

	reply(cl, json);
}

static void process_lines(struct client *cl);

/*
 * The sync timer runs with the lowest priority: when it is dispatched,
 * nothing else in the event loop is pending. Work in a worker is checked
 * separately.
 */
static int sync_check(sd_event_source *src,
		      uint64_t usec __attribute__((unused)), void *user_data)
{
	struct client *cl = user_data;
	struct control *c = cl->c;

	if (c->callbacks.busy && c->callbacks.busy(c->user_data)) {
		sd_event_source_set_time_relative(src, SYNC_RECHECK_USEC);
		sd_event_source_set_enabled(src, SD_EVENT_ONESHOT);
		return 0;
	}

	cl->sync_timer = sd_event_source_disable_unref(cl->sync_timer);
	reply(cl, "ok");

	// The requests after the sync were held back.
	process_lines(cl);
	if (cl->dead)
		client_free(cl);
	else
		update_events(cl);

	return 0;
}

static void handle_sync(struct client *cl)
{
	int r;

	r = sd_event_add_time_relative(cl->c->event, &cl->sync_timer,
				       CLOCK_MONOTONIC, 0, 0, sync_check, cl);
	if (r >= 0)
		r = sd_event_source_set_priority(cl->sync_timer,
						 SD_EVENT_PRIORITY_IDLE);
	if (r < 0) {
		cl->sync_timer = sd_event_source_disable_unref(cl->sync_timer);
		reply(cl, "error cannot wait");
	}

	// The requests after the sync are held back until it is answered.
}

static void handle_line(struct client *cl, char *line)
{
	char *tok[MAX_PROPS + 4];
	char *p = line, *t;
	int n = 0;

	while ((t = shr_strsep(&p, " \t")) != NULL) {
		if (!*t)
			continue;
		if (n == (int)ARRAY_SIZE(tok)) {
			reply(cl, "error too many arguments");
			return;
		}
		tok[n++] = t;
	}

	if (!n)
		reply(cl, "error empty request");
	else if (streq(tok[0], "uevent"))
		handle_uevent(cl, tok, n);
	else if (streq(tok[0], "sync") && n == 1)
		handle_sync(cl);
	else if (streq(tok[0], "dump") && n == 1)
		handle_dump(cl);
	else
		reply(cl, "error unknown request");
}

/*
 * Handle the complete lines in the buffer, up to a sync, or until the
 * socket takes no more replies.
 */
static void process_lines(struct client *cl)
{
	char *nl;

	while (!cl->dead && !cl->sync_timer && !cl->out_len &&
	       (nl = memchr(cl->buf, '\n', cl->len))) {
		size_t used = nl - cl->buf + 1;

		*nl = '\0';
		handle_line(cl, cl->buf);
		memmove(cl->buf, cl->buf + used, cl->len - used);
		cl->len -= used;
	}
}

static int on_client(sd_event_source *src __attribute__((unused)), int fd,
		     uint32_t revents, void *user_data)
{
	struct client *cl = user_data;
	ssize_t n;

	if (cl->out_len)
		flush(cl);

	if (!cl->dead && (revents & EPOLLIN) && !cl->out_len) {
		n = read(fd, cl->buf + cl->len, sizeof(cl->buf) - cl->len);
		if (n > 0)
			cl->len += n;
		else if (n == 0 || (errno != EINTR && errno != EAGAIN))
			cl->dead = true;
	}

	process_lines(cl);

	if (!cl->dead && cl->len == sizeof(cl->buf) &&
	    !memchr(cl->buf, '\n', cl->len)) {
		reply(cl, "error request too long");
		cl->dead = true;
	}

	if (cl->dead)
		client_free(cl);
	else
		update_events(cl);

	return 0;
}

static int on_accept(sd_event_source *src __attribute__((unused)), int fd,
		     uint32_t revents __attribute__((unused)), void *user_data)
{
	struct control *c = user_data;
	struct client *cl;
	int cfd, r;

	cfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (cfd < 0)
		return 0;

	cl = calloc(1, sizeof(*cl));
	if (!cl) {
		close(cfd);
		return 0;
	}
	cl->c = c;
	cl->fd = cfd;

	/*
	 * The lowest priority: a request is read when the event loop has
	 * nothing else to do, so the requests and the daemon's own work do
	 * not interleave.
	 */
	r = sd_event_add_io(c->event, &cl->io, cfd, EPOLLIN, on_client, cl);
	if (r >= 0)
		r = sd_event_source_set_priority(cl->io,
						 SD_EVENT_PRIORITY_IDLE);
	if (r < 0) {
		log_warn("control: %s", strerror(-r));
		sd_event_source_disable_unref(cl->io);
		close(cfd);
		free(cl);
		return 0;
	}

	list_add_tail(&c->clients, &cl->node);
	return 0;
}

int control_start(sd_event *event, const char *path,
		  const struct control_callbacks *callbacks, void *user_data,
		  struct control **ret)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct control *c;
	int r;

	if (strlen(path) >= sizeof(addr.sun_path))
		return -ENAMETOOLONG;
	memcpy(addr.sun_path, path, strlen(path) + 1);

	c = calloc(1, sizeof(*c));
	if (!c)
		return -ENOMEM;
	c->fd = -1;
	c->event = event;
	c->callbacks = *callbacks;
	c->user_data = user_data;
	list_head_init(&c->clients);
	c->path = strdup(path);
	if (!c->path) {
		free(c);
		return -ENOMEM;
	}

	c->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (c->fd < 0) {
		r = -errno;
		goto err;
	}

	unlink(path); // left over from an earlier run
	if (bind(c->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    chmod(path, 0600) < 0 || listen(c->fd, 4) < 0) {
		r = -errno;
		goto err;
	}

	r = sd_event_add_io(event, &c->listen_src, c->fd, EPOLLIN, on_accept,
			    c);
	if (r < 0)
		goto err;

	*ret = c;
	return 0;
err:
	if (c->fd >= 0)
		close(c->fd);
	free(c->path);
	free(c);
	return r;
}

void control_stop(struct control *c)
{
	struct client *cl, *next;

	if (!c)
		return;

	list_for_each_safe(&c->clients, cl, next, node)
		client_free(cl);
	sd_event_source_disable_unref(c->listen_src);
	close(c->fd);
	unlink(c->path);
	free(c->path);
	free(c);
}
