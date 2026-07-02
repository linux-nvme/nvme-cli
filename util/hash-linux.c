// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_alg.h>
#include <linux/socket.h>

#include <sys/socket.h>

#include "hash.h"

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define HMAC_SHA256_ALGO_NAME		"hmac(sha256)"
#define MD5_HASH_ALGO_NAME		"md5"
#define HMAC_SHA256_HASH_SIZE		32
#define MD5_HASH_HASH_SIZE		16

/*
 * Utility function to create hash value of given data (with given key) using
 * given hash algorithm; this function uses kernel crypto services
 */
static unsigned char *create_hash(const char *algo, int hash_size,
		unsigned char *data, int datalen, unsigned char *key,
		int keylen)
{
	int error, infd, outfd = -1;
	unsigned char *hash = NULL;
	struct sockaddr_alg provider_sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = { 0 }
	};

	/* copy algorithm name */
	if (strlen(algo) > sizeof(provider_sa.salg_name)) {
		fprintf(stderr, "%s: algorithm name overflow", __func__);
		return hash;
	}
	memcpy(provider_sa.salg_name, algo, strlen(algo));

	/* open netlink socket connection to algorigm provider and bind */
	infd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (infd < 0) {
		perror("socket");
		return hash;
	}
	error = bind(infd, (struct sockaddr *)&provider_sa,
		     sizeof(provider_sa));
	if (error < 0) {
		perror("bind");
		goto out_close_infd;
	}

	/* if algorithm requires key, set it first - empty keys not accepted !*/
	if (key != NULL && keylen > 0) {
		error = setsockopt(infd, SOL_ALG, ALG_SET_KEY, key, keylen);
		if (error < 0) {
			perror("setsockopt");
			goto out_close_infd;
		}
	}

	/* now send data to hash */
	outfd = accept(infd, NULL, 0);
	if (outfd < 0) {
		perror("accept");
		goto out_close_infd;
	}
	error = send(outfd, data, datalen, 0);
	if (error < 0) {
		perror("send");
		goto out_close_outfd;
	}

	/* read computed hash */
	hash = (unsigned char *)calloc(hash_size, 1);
	if (hash == NULL) {
		perror("calloc");
		goto out_close_outfd;
	}

	error = read(outfd, hash, hash_size);
	if (error != hash_size) {
		perror("read");
		free(hash);
		hash = NULL;
	}
out_close_outfd:
	close(outfd);
out_close_infd:
	close(infd);

	return hash;
}

/* Function that computes hmac-sha256 hash of given data and key pair. Returns
 * byte stream (non-null terminated) upon success, NULL otherwise.
 */
unsigned char *create_hmac_sha256(unsigned char *data, int datalen,
		unsigned char *key, int keylen)
{
	return create_hash(HMAC_SHA256_ALGO_NAME,
			   HMAC_SHA256_HASH_SIZE,
			   data,
			   datalen,
			   key,
			   keylen);
}

/* Function that computes md5 of given buffer.
 * Returns byte stream (non-null terminated) upon success, NULL otherwise.
 */
unsigned char *create_md5(unsigned char *data, int datalen)
{
	return create_hash(MD5_HASH_ALGO_NAME,
			   MD5_HASH_HASH_SIZE,
			   data,
			   datalen,
			   NULL,
			   0);
}
