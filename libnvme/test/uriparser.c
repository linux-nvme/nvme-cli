// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2024 Tomas Bzatek <tbzatek@redhat.com>
 */

#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include <ccan/array_size/array_size.h>

#include <libnvme.h>
#include <nvme/private.h>

struct test_data {
	const char *uri;
	/* parsed data */
	const char *scheme;
	const char *host;
	const char *user;
	const char *proto;
	int port;
	const char *path[7];
	const char *query;
	const char *frag;
};

static struct test_data test_data[] = {
	{ "nvme://192.168.1.1",  "nvme", "192.168.1.1" },
	{ "nvme://192.168.1.1/", "nvme", "192.168.1.1" },
	{ "nvme://192.168.1.1:1234",  "nvme", "192.168.1.1", .port = 1234 },
	{ "nvme://192.168.1.1:1234/", "nvme", "192.168.1.1", .port = 1234 },
	{ "nvme+tcp://192.168.1.1",   "nvme", "192.168.1.1", .proto = "tcp" },
	{ "nvme+rdma://192.168.1.1/", "nvme", "192.168.1.1", .proto = "rdma" },
	{ "nvme+tcp://192.168.1.1:1234",
	  "nvme", "192.168.1.1", .proto = "tcp", .port = 1234 },
	{ "nvme+tcp://192.168.1.1:1234/",
	  "nvme", "192.168.1.1", .proto = "tcp", .port = 1234 },
	{ "nvme+tcp://192.168.1.1:4420/path",
	  "nvme", "192.168.1.1", .proto = "tcp", .port = 4420,
	  .path = { "path", NULL }},
	{ "nvme+tcp://192.168.1.1/path/",
	  "nvme", "192.168.1.1", .proto = "tcp", .path = { "path", NULL }},
	{ "nvme+tcp://192.168.1.1:4420/p1/p2/p3",
	  "nvme", "192.168.1.1", .proto = "tcp", .port = 4420,
	  .path = { "p1", "p2", "p3", NULL }},
	{ "nvme+tcp://192.168.1.1:4420/p1/p2/p3/",
	  "nvme", "192.168.1.1", .proto = "tcp", .port = 4420,
	  .path = { "p1", "p2", "p3", NULL }},
	{ "nvme+tcp://192.168.1.1:4420//p1//p2/////p3",
	  "nvme", "192.168.1.1", .proto = "tcp", .port = 4420,
	  .path = { "p1", "p2", "p3", NULL }},
	{ "nvme+tcp://192.168.1.1:4420//p1//p2/////p3/",
	  "nvme", "192.168.1.1", .proto = "tcp", .port = 4420,
	  .path = { "p1", "p2", "p3", NULL }},
	{ "nvme://[fe80::1010]",  "nvme", "fe80::1010" },
	{ "nvme://[fe80::1010]/", "nvme", "fe80::1010" },
	{ "nvme://[fe80::1010]:1234",  "nvme", "fe80::1010", .port = 1234 },
	{ "nvme://[fe80::1010]:1234/", "nvme", "fe80::1010", .port = 1234 },
	{ "nvme+tcp://[fe80::1010]",   "nvme", "fe80::1010", .proto = "tcp" },
	{ "nvme+rdma://[fe80::1010]/", "nvme", "fe80::1010", .proto = "rdma" },
	{ "nvme+tcp://[fe80::1010]:1234",
	  "nvme", "fe80::1010", .proto = "tcp", .port = 1234 },
	{ "nvme+tcp://[fe80::1010]:1234/",
	  "nvme", "fe80::1010", .proto = "tcp", .port = 1234 },
	{ "nvme+tcp://[fe80::1010]:4420/path",
	  "nvme", "fe80::1010", .proto = "tcp", .port = 4420,
	  .path = { "path", NULL }},
	{ "nvme+tcp://[fe80::1010]/path/",
	  "nvme", "fe80::1010", .proto = "tcp", .path = { "path", NULL }},
	{ "nvme+tcp://[fe80::1010]:4420/p1/p2/p3",
	  "nvme", "fe80::1010", .proto = "tcp", .port = 4420,
	  .path = { "p1", "p2", "p3", NULL }},
	{ "nvme+tcp://[fe80::fc7d:8cff:fe5b:962e]:666/p1/p2/p3/",
	  "nvme", "fe80::fc7d:8cff:fe5b:962e", .proto = "tcp", .port = 666,
	  .path = { "p1", "p2", "p3", NULL }},
	{ "nvme://h?query",  "nvme", "h", .query = "query" },
	{ "nvme://h/?query", "nvme", "h", .query = "query" },
	{ "nvme://h/x?query",
	  "nvme", "h", .path = { "x" }, .query = "query" },
	{ "nvme://h/p1/?query",
	  "nvme", "h", .path = { "p1" }, .query = "query" },
	{ "nvme://h/p1/x?query",
	  "nvme", "h", .path = { "p1", "x" }, .query = "query" },
	{ "nvme://h#fragment",  "nvme", "h", .frag = "fragment" },
	{ "nvme://h/#fragment", "nvme", "h", .frag = "fragment" },
	{ "nvme://h/x#fragment",
	  "nvme", "h", .path = { "x" }, .frag = "fragment" },
	{ "nvme://h/p1/#fragment",
	  "nvme", "h", .path = { "p1" }, .frag = "fragment" },
	{ "nvme://h/p1/x#fragment",
	  "nvme", "h", .path = { "p1", "x" }, .frag = "fragment" },
	{ "nvme://h/?query#fragment",
	  "nvme", "h", .query = "query", .frag = "fragment" },
	{ "nvme://h/x?query#fragment",
	  "nvme", "h", .path = { "x" }, .query = "query", .frag = "fragment" },
	{ "nvme://h/p1/?query#fragment",
	  "nvme", "h", .path = { "p1" }, .query = "query", .frag = "fragment" },
	{ "nvme://h/p1/x?query#fragment",
	  "nvme", "h", .path = { "p1", "x" }, .query = "query",
	   .frag = "fragment" },
	{ "nvme://h/#fragment?query",
	  "nvme", "h", .frag = "fragment?query" },
	{ "nvme://h/x#fragment?query",
	  "nvme", "h", .path = { "x" }, .frag = "fragment?query" },
	{ "nvme://h/p1/#fragment?query",
	  "nvme", "h", .path = { "p1" }, .frag = "fragment?query" },
	{ "nvme://h/p1/x#fragment?query",
	  "nvme", "h", .path = { "p1", "x" }, .frag = "fragment?query" },
	{ "nvme://user@h",  "nvme", "h", .user = "user" },
	{ "nvme://user@h/", "nvme", "h", .user = "user" },
	{ "nvme://user:pass@h/", "nvme", "h", .user = "user:pass" },
	{ "nvme://[fe80::1010]@h/", "nvme", "h", .user = "[fe80::1010]" },
	{ "nvme://u[fe80::1010]@h/", "nvme", "h", .user = "u[fe80::1010]" },
	{ "nvme://u[aa:bb::cc]@h/", "nvme", "h", .user = "u[aa:bb::cc]" },
	{ "nvme+rdma://u[aa:bb::cc]@[aa:bb::cc]:12345/p1/x?q=val#fr",
	  "nvme", "aa:bb::cc", .proto = "rdma", .port = 12345,
	  .user = "u[aa:bb::cc]", .path = { "p1", "x" },
	  .query = "q=val", .frag = "fr" },
	{ "nvme://ex%5Cmp%3Ae",  "nvme", "ex\\mp:e" },
	{ "nvme://ex%5Cmp%3Ae.com/", "nvme", "ex\\mp:e.com" },
	{ "nvme://u%24er@ex%5Cmp%3Ae.com/", "nvme", "ex\\mp:e.com",
	  .user = "u$er" },
	{ "nvme+tcp://ex%5Cmp%3Ae.com:1234",
	  "nvme", "ex\\mp:e.com", .proto = "tcp", .port = 1234 },
	{ "nvme+tcp://ex%5Cmp%3Ae.com:1234/p1/ex%3Camp%3Ele/p3",
	  "nvme", "ex\\mp:e.com", .proto = "tcp", .port = 1234,
	  .path = { "p1", "ex<amp>le", "p3", NULL } },
	{ "nvme+tcp://ex%5Cmp%3Ae.com:1234/p1/%3C%3E/p3?q%5E%24ry#fr%26gm%23nt",
	  "nvme", "ex\\mp:e.com", .proto = "tcp", .port = 1234,
	  .path = { "p1", "<>", "p3", NULL }, .query = "q^$ry",
	  .frag = "fr&gm#nt" },
};

const char *test_data_bad[] = {
	"",
	" ",
	"nonsense",
	"vnme:",
	"vnme:/",
	"vnme://",
	"vnme:///",
	"vnme+foo://",
	"nvme:hostname/",
	"nvme:/hostname/",
	"nvme:///hostname/",
	"nvme+foo:///hostname/",
};

static void test_uriparser(void)
{
	printf("Testing URI parser:\n");
	for (int i = 0; i < ARRAY_SIZE(test_data); i++) {
		const struct test_data *d = &test_data[i];
		struct nvme_fabrics_uri *parsed_data;
		char **s;
		int i;

		printf(" '%s'...", d->uri);
		assert(!nvme_parse_uri(d->uri, &parsed_data));

		assert(strcmp(d->scheme, parsed_data->scheme) == 0);
		if (d->proto) {
			assert(parsed_data->protocol != NULL);
			assert(strcmp(d->proto, parsed_data->protocol) == 0);
		} else
			assert(d->proto == parsed_data->protocol);
		assert(strcmp(d->host, parsed_data->host) == 0);
		assert(d->port == parsed_data->port);

		if (!parsed_data->path_segments)
			assert(d->path[0] == NULL);
		else {
			for (i = 0, s = parsed_data->path_segments;
			     s && *s; s++, i++) {
				assert(d->path[i] != NULL);
				assert(strcmp(d->path[i], *s) == 0);
			}
			/* trailing NULL element */
			assert(d->path[i] == parsed_data->path_segments[i]);
		}
		if (d->query) {
			assert(parsed_data->query != NULL);
			assert(strcmp(d->query, parsed_data->query) == 0);
		} else
			assert(d->query == parsed_data->query);
		if (d->frag) {
			assert(parsed_data->fragment != NULL);
			assert(strcmp(d->frag, parsed_data->fragment) == 0);
		} else
			assert(d->frag == parsed_data->fragment);
		nvme_free_uri(parsed_data);
		printf("  OK\n");
	}
}

static void test_uriparser_bad(void)
{
	printf("Testing malformed URI strings:\n");
	for (int i = 0; i < ARRAY_SIZE(test_data_bad); i++) {
		struct nvme_fabrics_uri *parsed_data = NULL;

		printf(" '%s'...", test_data_bad[i]);
		assert(nvme_parse_uri(test_data_bad[i], &parsed_data));
		assert(parsed_data == NULL);
		printf("   OK\n");
	}
}

int main(int argc, char *argv[])
{
	test_uriparser();
	test_uriparser_bad();

	fflush(stdout);

	return 0;
}
