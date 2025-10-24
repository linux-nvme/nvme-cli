// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 Micron Technology Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * nvme-rpmb.c - Implementation of NVMe RPMB support commands in Nvme
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <linux/socket.h>
#include <limits.h>

#include "common.h"
#include "nvme.h"
#include "libnvme.h"
#include "nvme-print.h"

#define CREATE_CMD


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
unsigned char *create_hash(const char *algo,
			   int hash_size,
			   unsigned char *data,
			   int datalen,
			   unsigned char *key,
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
    	error = bind(infd, (struct sockaddr *)&provider_sa, sizeof(provider_sa));
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
unsigned char *hmac_sha256(unsigned char *data, int datalen, unsigned char *key,
			   int keylen)
{
	return create_hash(HMAC_SHA256_ALGO_NAME,
			   HMAC_SHA256_HASH_SIZE,
			   data,
			   datalen,
			   key,
			   keylen);
}

/* Function that computes md5 of given buffer - md5 hash is used as nonce
 * Returns byte stream (non-null terminated) upon success, NULL otherwise.
 */
unsigned char *rpmb_md5(unsigned char *data, int datalen)
{
	return create_hash(MD5_HASH_ALGO_NAME,
			   MD5_HASH_HASH_SIZE,
			   data,
			   datalen,
			   NULL,
			   0);
}

/* Read data from given file into buffer and return its length */
static int read_file(const char *file, unsigned char **data, unsigned int *len)
{
	struct stat sb;
	size_t size;
	unsigned char   *buf = NULL;
	int fd;
	int err = -EINVAL;

	if (file == NULL) return err;

	if ((fd = open(file, O_RDONLY)) < 0) {
		fprintf(stderr, "Failed to open %s: %s\n", file, strerror(errno));
		return fd;
	}

	err = fstat(fd, &sb);
	if (err < 0) {
		perror("fstat");
		goto out;
	}

	size = sb.st_size;
	if (posix_memalign((void **)&buf, getpagesize(), size)) {
		fprintf(stderr, "No memory for reading file :%s\n", file);
		err = -ENOMEM;
		goto out;
	}

	err = read(fd, buf, size);
	if (err < 0) {
		err = -errno;
		fprintf(stderr, "Failed to read data from file"
				" %s with %s\n", file, strerror(errno));
		free(buf);
		goto out;
	}
	*data = buf; 
	*len = err;
	err = 0;
out:
	close(fd);
	return err;
}

/* Write given buffer data to specified file */
static void write_file(unsigned char *data, size_t len, const char *dir,
		       const char *file, const char *msg)
{
	char temp_folder[PATH_MAX] = { 0 };
	_cleanup_file_ FILE *fp = NULL;

	if (dir != NULL)
		sprintf(temp_folder, "%s/%s", dir, file);
	else
		sprintf(temp_folder, "./%s", file);

	if ((fp = fopen(temp_folder, "ab+")) != NULL) {
		if (fwrite(data, 1, len,  fp) != len) {
			fprintf(stderr, "Failed to write %s data to %s\n",
				 msg ? msg : "", temp_folder);
		}
	} else  {
		fprintf(stderr, "Failed to open %s file to write %s\n",
			temp_folder, msg ? msg : "");
	}
}

/* Various definitions used in RPMB related support */
enum rpmb_request_type {
	RPMB_REQ_AUTH_KEY_PROGRAM = 0x0001,
	RPMB_REQ_READ_WRITE_CNTR  = 0x0002,
	RPMB_REQ_AUTH_DATA_WRITE  = 0x0003,
	RPMB_REQ_AUTH_DATA_READ   = 0x0004,
	RPMB_REQ_READ_RESULT      = 0x0005,
	RPMB_REQ_AUTH_DCB_WRITE   = 0x0006,
	RPMB_REQ_AUTH_DCB_READ    = 0x0007
};
	
enum rpmb_response_type {
	RPMB_RSP_AUTH_KEY_PROGRAM = (RPMB_REQ_AUTH_KEY_PROGRAM << 8),
	RPMB_RSP_READ_WRITE_CNTR  = (RPMB_REQ_READ_WRITE_CNTR  << 8),
	RPMB_RSP_AUTH_DATA_WRITE  = (RPMB_REQ_AUTH_DATA_WRITE  << 8),
	RPMB_RSP_AUTH_DATA_READ   = (RPMB_REQ_AUTH_DATA_READ   << 8),
	RPMB_RSP_READ_RESULT      = (RPMB_REQ_READ_RESULT      << 8),
	RPMB_RSP_AUTH_DCB_WRITE   = (RPMB_REQ_AUTH_DCB_WRITE   << 8),
	RPMB_RSP_AUTH_DCB_READ    = (RPMB_REQ_AUTH_DCB_READ    << 8)
};

/* RPMB data frame structure */
#pragma pack(1)
struct rpmb_data_frame_t {
	unsigned char  pad[191];
	unsigned char  mac[32];
	unsigned char  target;     /* 0-6, should match with NSSF with SS, SR */
	unsigned char  nonce[16];
	unsigned int   write_counter;
	unsigned int   address;
	unsigned int   sectors;
	unsigned short result;
	unsigned short type;       /* req or response */
	unsigned char  data[0];    /* in sector count times */
};
#pragma pack()
	
struct rpmb_config_block_t {
	unsigned char  bp_enable;
	unsigned char  bp_lock;
	unsigned char  rsvd[510]; 
};

#define RPMB_DATA_FRAME_SIZE  256
#define RPMB_NVME_SECP        0xEA 
#define RPMB_NVME_SPSP        0x0001

static int send_rpmb_req(struct nvme_transport_handle *hdl, unsigned char tgt,
			 int size, struct rpmb_data_frame_t *req)
{
	struct nvme_security_send_args args = {
		.args_size	= sizeof(args),
		.nsid		= 0,
		.nssf		= tgt,
		.spsp0		= RPMB_NVME_SPSP,
		.spsp1		= 0,
		.secp		= RPMB_NVME_SECP,
		.tl		= 0,
		.data_len	= size,
		.data		= (void *)req,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};

	return nvme_security_send(hdl, &args);
}

static int recv_rpmb_rsp(struct nvme_transport_handle *hdl, int tgt, int size,
			 struct rpmb_data_frame_t *rsp)
{

	struct nvme_security_receive_args args = {
		.args_size	= sizeof(args),
		.nsid		= 0,
		.nssf		= tgt,
		.spsp0		= RPMB_NVME_SPSP,
		.spsp1		= 0,
		.secp		= RPMB_NVME_SECP,
		.al		= 0,
		.data_len	= size,
		.data		= (void *)rsp,
		.timeout	= NVME_DEFAULT_IOCTL_TIMEOUT,
		.result		= NULL,
	};

	return nvme_security_receive(hdl, &args);
}

/* Initialize nonce value in rpmb request frame */
static void rpmb_nonce_init(struct rpmb_data_frame_t *req)
{
	int num = rand();
	unsigned char *hash = rpmb_md5((unsigned char *)&num, sizeof(num));
	if (hash) memcpy(req->nonce, hash, sizeof(req->nonce));
}

/* Read key from a given key buffer or key file */
static unsigned char *read_rpmb_key(char *keystr, char *keyfile, unsigned int *keysize)
{
	unsigned char *keybuf = NULL;
	int err;
	
	if (keystr == NULL) {
		if (keyfile != NULL) {
			err = read_file(keyfile, &keybuf, keysize);
			if (err < 0)
				return NULL;
		}
	} else if ((keybuf = (unsigned char *)malloc(strlen(keystr))) != NULL) {
		*keysize = strlen(keystr);
		memcpy(keybuf, keystr, *keysize);
	}

	return keybuf;
}

/* Initialize RPMB request frame with given values */
static struct rpmb_data_frame_t *
rpmb_request_init(unsigned int   req_size,
		  unsigned short type,
		  unsigned char  target,
		  unsigned char  nonce,
		  unsigned int   addr,
		  unsigned int   sectors,
		  unsigned char  *data,
		  unsigned short data_offset,
		  unsigned int   data_size)
{
	struct rpmb_data_frame_t *req = NULL;

	if ((req = (struct rpmb_data_frame_t *)calloc(req_size, 1)) == NULL) {
		fprintf(stderr, "Memory allocation failed for request 0x%04x\n",
			type);
		return req;
	}

	req->type = type;
	req->target = target;
	req->address = addr;
	req->sectors = sectors;
	
	if (nonce) rpmb_nonce_init(req);
	if (data)  memcpy((unsigned char *)req + data_offset, data, data_size);

	return req;
}

/* Process rpmb response and print appropriate error message */
static int check_rpmb_response(struct rpmb_data_frame_t *req,
			       struct rpmb_data_frame_t *rsp, char *msg)
{
	const char *rpmb_result_string [] = {
		"Operation successful", 
		"General failure",
		"Authentication (MAC) failure",
		"Counter failure (not matching/incrementing failure)",
		"Address failure (out of range or wrong alignment)",
		"Write (data/counter/result) failure",
		"Read (data/counter/result) failure",
		"Authentication key not yet programmed",
		"Invalid device configuration block",
		"Unknown error"
	};
	 
	/* check error status before comparing nonce and mac */
	if (rsp->result != 0)  {
		if (rsp->type != ((req->type << 8) & 0xFF00)) {
			fprintf(stderr, "%s ! non-matching response 0x%04x for"
				" 0x%04x\n", msg, rsp->type, req->type);
		} else if ((rsp->result & 0x80) == 0x80) {
			fprintf(stderr, "%s ! Expired write-counter !\n", msg);
		} else if (rsp->result) {
			fprintf(stderr, "%s ! %s\n", msg,
				rpmb_result_string[rsp->result & 0x7F]);
		} else if (memcmp(req->nonce, rsp->nonce, 16)) {
			fprintf(stderr, "%s ! non-matching nonce\n", msg);
		} else if (memcmp(req->mac, rsp->mac, 32)) {
			fprintf(stderr, "%s ! non-matching MAC\n", msg);
		} else if ((req->write_counter + 1) != rsp->write_counter) {
			fprintf(stderr, "%s ! out-of-sync write-counters\n", msg);
		}
	}
	
	return (int)(rsp->result);
}

/* send an initialized rpmb request to the controller and read its response
 * expected response size give in 'rsp_size'. returns response buffer upon
 * successful completion (caller must free), NULL otherwise
 */
static struct rpmb_data_frame_t *
rpmb_read_request(struct nvme_transport_handle *hdl,
		  struct rpmb_data_frame_t *req,
		  int req_size,
		  int rsp_size)
{
	struct rpmb_data_frame_t *rsp = NULL;
	unsigned char msg[1024] = { 0 };
	int error;

	sprintf((char *)msg, "RPMB request 0x%04x to target 0x%x",
		req->type, req->target);

	error = send_rpmb_req(hdl, req->target, req_size, req);
	if (error != 0) {
		fprintf(stderr, "%s failed with error = 0x%x\n",
			msg, error);
		goto error_out;
	}

	/* read the result back */
	rsp = (struct rpmb_data_frame_t *)calloc(rsp_size, 1);
	if (rsp == NULL) {
		fprintf(stderr, "memory alloc failed for %s\n", msg);
		goto error_out;
	}

	/* Read result of previous request */
	error = recv_rpmb_rsp(hdl, req->target, rsp_size, rsp);
	if (error) {
		fprintf(stderr, "error 0x%x receiving response for %s\n",
			error, msg);
		goto error_out;
	}

	/* validate response buffer - match target, nonce, and mac */
	error = check_rpmb_response(req, rsp, (char *)msg);
	if (error == 0) return rsp;

error_out:
	free(rsp);
	return NULL;
}

/* read current write counter value from controller */
static int rpmb_read_write_counter(struct nvme_transport_handle *hdl,
				   unsigned char target,
				   unsigned int *counter)
{
	int error = -1;
	int req_size = sizeof(struct rpmb_data_frame_t);
	struct rpmb_data_frame_t *req = NULL;
	struct rpmb_data_frame_t *rsp = NULL;

	req = rpmb_request_init(req_size, RPMB_REQ_READ_WRITE_CNTR,
				target, 1, 0, 0, NULL, 0, 0);
	if (req == NULL) goto out;
	if ((rsp = rpmb_read_request(hdl, req, req_size, req_size)) == NULL) {
		goto out;
	}	
	*counter = rsp->write_counter; 
	error = 0;
	
out:
	free(req);
	free(rsp);
	return error;
}

/* Read current device configuration block into specified buffer. It also returns
 * current write counter value returned as part of response, in case of error it
 * returns 0
 */
static unsigned int rpmb_read_config_block(struct nvme_transport_handle *hdl,
					   unsigned char **config_buf)
{
	int req_size = sizeof(struct rpmb_data_frame_t);
	int cfg_size = sizeof(struct rpmb_config_block_t);
	int rsp_size = req_size + cfg_size;
	
	struct rpmb_data_frame_t   *req = NULL;
	struct rpmb_data_frame_t   *rsp = NULL;
	struct rpmb_config_block_t *cfg = NULL;
	unsigned int retval = 0;

	/* initialize request with nonce, no data on input */
	req = rpmb_request_init(req_size, RPMB_REQ_AUTH_DCB_READ, 0, 1, 0, 1,
				0, 0, 0);
	if (!req)
		return 0;
	if ((rsp = rpmb_read_request(hdl, req, req_size, rsp_size)) == NULL)
	{
		free(req);
		return 0;
	}	

	/* copy configuration data to be sent back to caller */
	cfg = (struct rpmb_config_block_t *)calloc(cfg_size, 1);
	if (cfg == NULL) {
		fprintf(stderr, "failed to allocate RPMB config buffer\n");
		goto out;
	}

	memcpy(cfg, rsp->data, cfg_size);
	*config_buf = (unsigned char *)cfg;
	cfg = NULL;
	retval = rsp->write_counter;
out:
	free(req);
	free(rsp);
	return retval;
}


static int rpmb_auth_data_read(struct nvme_transport_handle *hdl,
			       unsigned char target,
			       unsigned int offset,
			       unsigned char **msg_buf,
			       int msg_size, int acc_size)
{
	struct rpmb_data_frame_t *req = NULL;
	struct rpmb_data_frame_t *rsp = NULL;
	int req_size = sizeof(struct rpmb_data_frame_t);
	int chunk_size = (acc_size < msg_size) ? acc_size : msg_size;
	int xfer = chunk_size;
	unsigned char *bufp = (unsigned char *)malloc(msg_size * 512);
	unsigned char *tbufp = bufp;
	int data_size, rsp_size;
	int error = -1;

	if (bufp == NULL) {
		fprintf(stderr, "Failed to allocated memory for read-data req\n");
		goto out;
	}
	
	while (xfer > 0) {
		rsp_size = req_size + xfer * 512;
		req = rpmb_request_init(req_size, RPMB_REQ_AUTH_DATA_READ,
					target, 1, offset, xfer, 0, 0, 0);
		if (req == NULL)
			break;
		if ((rsp = rpmb_read_request(hdl, req, req_size, rsp_size)) == NULL)
		{
			fprintf(stderr, "read_request failed\n");
			free(req);
			break;
		}

		data_size = rsp->sectors * 512;
		memcpy(tbufp, rsp->data, data_size);
		offset += rsp->sectors;
		tbufp += data_size;
		if (offset + chunk_size > msg_size)
			xfer = msg_size - offset;
		else 
			xfer = chunk_size;
		free(req);
		free(rsp);
	}
	
	*msg_buf = bufp;
	error = offset;
out:
	return error;
}

/* Implementation of programming authentication key to given RPMB target */
static int rpmb_program_auth_key(struct nvme_transport_handle *hdl,
				 unsigned char target, unsigned char *key_buf,
				 int key_size)
{
	int req_size = sizeof(struct rpmb_data_frame_t);
	int rsp_size = sizeof(struct rpmb_data_frame_t);
	
	struct rpmb_data_frame_t *req = NULL;
	struct rpmb_data_frame_t *rsp = NULL;
	
	int err = -ENOMEM;
	
	req = rpmb_request_init(req_size, RPMB_REQ_AUTH_KEY_PROGRAM, target,
				0, 0, 0, key_buf, (223 - key_size), key_size);
	if (req == NULL) {
		fprintf(stderr, "failed to allocate request buffer memory\n");
		goto out;
	}

	/* send the request and get response */
	err = send_rpmb_req(hdl, req->target, req_size, req);
	if (err) {
		fprintf(stderr, "RPMB request 0x%04x for 0x%x, err: %d\n", req->type, req->target,
			err);
		goto out;
	}

	/* send the request to get the result and then request to get the response */
	rsp = (struct rpmb_data_frame_t *)calloc(rsp_size, 1);
	if (!rsp) {
		fprintf(stderr, "failed to allocate response buffer memory\n");
		err = -ENOMEM;
		goto out;
	}

	rsp->target = req->target;
	rsp->type = RPMB_REQ_READ_RESULT;
	err = send_rpmb_req(hdl, req->target, rsp_size, rsp);
	if (err || rsp->result) {
		fprintf(stderr, "Program auth key read result 0x%x, error = 0x%x\n", rsp->result,
			err);
		goto out;
	}

	/* reuse response buffer */
	memset(rsp, 0, rsp_size);
	err = recv_rpmb_rsp(hdl, req->target, rsp_size, rsp);
	if (err != 0)
		fprintf(stderr, "Program Key recv error = 0x%x\n", err);
	else
		err = check_rpmb_response(req, rsp, "Failed to Program Key");
out:
	free(req);
	free(rsp);
	
	return err;
}


/* Implementation of RPMB authenticated data write command; this function
 * transfers msg_size bytes from msg_buf to controller 'addr'. Returns
 * number of bytes actually written to, otherwise negetive error code
 * on failures.
 */
static int auth_data_write_chunk(struct nvme_transport_handle *hdl,
				 unsigned char tgt, unsigned int addr,
				 unsigned char *msg_buf, int msg_size,
				 unsigned char *keybuf, int keysize)
{
	int req_size = sizeof(struct rpmb_data_frame_t) + msg_size;
	int rsp_size = sizeof(struct rpmb_data_frame_t);
	
	struct rpmb_data_frame_t *req = NULL;
	struct rpmb_data_frame_t *rsp = NULL;
	
	unsigned int write_cntr = 0;
	unsigned char *mac = NULL;
	int error  = -ENOMEM;

	/* get current write counter and copy to the request  */
	error = rpmb_read_write_counter(hdl, tgt, &write_cntr);
	if (error != 0) {
	   fprintf(stderr, "Failed to read write counter for write-data\n");
	    goto out;
	}
	
	req = rpmb_request_init(req_size, RPMB_REQ_AUTH_DATA_WRITE, tgt, 0,
				addr, (msg_size / 512), msg_buf,
				offsetof(struct rpmb_data_frame_t, data), msg_size);
	if (req == NULL) {
		fprintf(stderr, "Memory alloc failed for write-data command\n");
		goto out;
	}

	req->write_counter = write_cntr;

	/* compute HMAC hash */
	mac = hmac_sha256(((unsigned char *)req + 223), req_size - 223,
			   keybuf, keysize);
	if (mac == NULL) {
		fprintf(stderr, "failed to compute HMAC-SHA256\n");
		error = -1;
		goto out;
	}

	memcpy(req->mac, mac, 32);
	
	/* send the request and get response */
	error = send_rpmb_req(hdl, tgt, req_size, req);
	if (error != 0) {
	    fprintf(stderr, "RPMB request 0x%04x for 0x%x, error: %d\n",
		    req->type, tgt, error);
	    goto out;
	}
	
	/* send the request to get the result and then request to get the response */
        rsp = (struct rpmb_data_frame_t *)calloc(rsp_size, 1);
	rsp->target = req->target;
	rsp->type = RPMB_REQ_READ_RESULT;
	error = send_rpmb_req(hdl, tgt, rsp_size, rsp);
	if (error != 0 || rsp->result != 0) {
		fprintf(stderr, "Write-data read result 0x%x, error = 0x%x\n",
			rsp->result, error);
		goto out;
	}

	/* Read final response */
	memset(rsp, 0, rsp_size);
	error = recv_rpmb_rsp(hdl, tgt, rsp_size, rsp);
	if (error != 0)
		fprintf(stderr, "Auth data write recv error = 0x%x\n", error);
	else 
    		error = check_rpmb_response(req, rsp, "Failed to write-data");
out:
	free(req);
	free(rsp);
	free(mac);

	return error;
}

/* send the request and get response */
static int rpmb_auth_data_write(struct nvme_transport_handle *hdl,
				unsigned char target, unsigned int addr,
				int acc_size, unsigned char *msg_buf,
				int msg_size, unsigned char *keybuf,
				int keysize)
{
	int chunk_size = acc_size < msg_size ? acc_size : msg_size;
	int xfer   = chunk_size;
	int offset = 0;

	while (xfer > 0 ) {
		if (auth_data_write_chunk(hdl, target, (addr + offset / 512),
				          msg_buf + offset, xfer,
				          keybuf, keysize) != 0)
		{
			/* error writing chunk data */
			break;	
		}

		offset += xfer;
		if (offset + chunk_size > msg_size)
			xfer = msg_size - offset;
		else 
			xfer = chunk_size;
	}

	return offset;
}

/* writes given config_block buffer to the drive target 0 */
static int rpmb_write_config_block(struct nvme_transport_handle *hdl,
				   unsigned char *cfg_buf,
				   unsigned char *keybuf, int keysize)
{
	int cfg_size = sizeof(struct rpmb_config_block_t);
	int rsp_size = sizeof(struct rpmb_data_frame_t);
	int req_size = rsp_size + cfg_size;
	
	struct rpmb_data_frame_t *req = NULL;
	struct rpmb_data_frame_t *rsp = NULL;
	unsigned char *cfg_buf_read = NULL, *mac = NULL;
	unsigned int write_cntr = 0;
	int   error = -ENOMEM;
	
	/* initialize request */
	req = rpmb_request_init(req_size, RPMB_REQ_AUTH_DCB_WRITE, 0, 0, 0, 1,
				cfg_buf, offsetof(struct rpmb_data_frame_t, data),
				cfg_size);
	if (req == NULL) {
		fprintf(stderr, "failed to allocate rpmb request buffer\n");
		goto out; 
	}

	/* read config block write_counter from controller */
	write_cntr = rpmb_read_config_block(hdl, &cfg_buf_read);
	if (cfg_buf_read == NULL) {
	    	fprintf(stderr, "failed to read config block write counter\n");
		error = -EIO;
	    	goto out;
	}

	free(cfg_buf_read);
	req->write_counter = write_cntr;
	mac = hmac_sha256(((unsigned char *)req + 223), req_size - 223,
			   keybuf, keysize);
	if (mac == NULL) {
		fprintf(stderr, "failed to compute hmac-sha256 hash\n");
		error = -EINVAL;
	    	goto out;
	}
	
	memcpy(req->mac, mac, sizeof(req->mac)); 
	
	error = send_rpmb_req(hdl, 0, req_size, req);
	if (error != 0) {
		fprintf(stderr, "Write-config RPMB request, error = 0x%x\n",
			error);
		goto out;
	}
	
	/* get response */
	rsp = (struct rpmb_data_frame_t *)calloc(rsp_size, 1);
	if (rsp == NULL) {
		fprintf(stderr, "failed to allocate response buffer memory\n");
		error = -ENOMEM;
		goto out;
	}

	/* get result first */
	memset(rsp, 0, rsp_size);
	rsp->target = req->target;
	rsp->type = RPMB_REQ_READ_RESULT;
	/* get the response and validate */
	error = recv_rpmb_rsp(hdl, req->target, rsp_size, rsp);
	if (error != 0) {
		fprintf(stderr,"Failed getting write-config response\
			error = 0x%x\n", error);
		goto out;
	}
	error = check_rpmb_response(req, rsp,
				  "Failed to retrieve write-config response");
out:
	free(req);
	free(rsp);
	free(mac);
	
	return error;
}

static bool invalid_xfer_size(int blocks, unsigned int bpsz)
{
	return ((blocks <= 0) || 
		(blocks * 512) > ((bpsz + 1) * 128 * 1024));
}

/* Handling rpmb sub-command */
int rpmb_cmd_option(int argc, char **argv, struct command *acmd, struct plugin *plugin)
{
	const char *desc    = "Run RPMB command on the supporting controller";
	const char *msg     = "data to be written on write-data or write-config commands";
	const char *mfile   = "data file for read/write-data, read/write-config options";
	const char *kfile   = "key file that has authentication key to be used";
	const char *target  = "RPMB target - numerical value of 0 to 6, default 0";
	const char *address = "Sector offset to read from or write to for an RPMB target, default 0";
	const char *blocks  = "Number of 512 blocks to read or write";
	const char *key     = "key to be used for authentication";
	const char *opt     = "RPMB action - info, program-key, read-counter, write-data, " \
			      "read-data, write-config and read-config";
	
	struct config {
		char *cmd;
		char *key;
		char *msg;
		char *keyfile;
		char *msgfile;
		int  opt;
		int  address;
		int  blocks; 
		char target;
	};
	
	struct config cfg = {
		.cmd     = "info",
		.key     = NULL,
		.msg     = NULL,
		.msgfile = NULL,
		.keyfile = NULL,
		.opt     = 0,
		.address = 0,
		.blocks  = 0,
		.target  = 0,
	};
	
	OPT_ARGS(opts) = {
		OPT_STRING("cmd",     'c', "command", &cfg.cmd,     opt),
		OPT_STRING("msgfile", 'f', "FILE",    &cfg.msgfile, mfile),
		OPT_STRING("keyfile", 'g', "FILE",    &cfg.keyfile, kfile),
		OPT_STRING("key",     'k', "key",     &cfg.key,     key),
		OPT_STRING("msg",     'd', "data",    &cfg.msg,     msg),
		OPT_UINT("address",   'o', &cfg.address,  address),
		OPT_UINT("blocks",    'b', &cfg.blocks,   blocks),
		OPT_UINT("target",    't', &cfg.target,   target),
		OPT_END()
	};
	
	_cleanup_free_ unsigned char *key_buf = NULL;
	_cleanup_free_ unsigned char *msg_buf = NULL;
	_cleanup_nvme_global_ctx_ struct nvme_global_ctx *ctx = NULL;
	_cleanup_nvme_transport_handle_ struct nvme_transport_handle *hdl = NULL;
	unsigned int write_cntr = 0;
	unsigned int msg_size = 0;
	unsigned int key_size = 0;
	struct nvme_id_ctrl ctrl;
	int err = -1;

	union ctrl_rpmbs_reg {
		struct {
			unsigned int num_targets:3;
			unsigned int auth_method:3;
			unsigned int reserved:10;
			unsigned int total_size:8;   /* 128K units */
			unsigned int access_size:8;  /* in 512 byte count */
		};
		unsigned int rpmbs;
	} regs;

	if ((err = parse_and_open(&ctx, &hdl, argc, argv, desc, opts)))
		return err;
	
	/* before parsing  commands, check if controller supports any RPMB targets */
	err = nvme_identify_ctrl(hdl, &ctrl);
	if (err)
		return err;
	
	regs.rpmbs = le32_to_cpu(ctrl.rpmbs);
	if (regs.num_targets == 0) {
		fprintf(stderr, "No RPMB targets are supported by the drive\n");
		return -1;
	}
	
	/* parse and validate options; default print rpmb support info */
	if (cfg.cmd == 0 || strcmp(cfg.cmd, "info") == 0) {
		nvme_show_id_ctrl_rpmbs(regs.rpmbs, 0);
		return -1;
	}
	
	if (strcmp(cfg.cmd, "program-key") == 0)
		cfg.opt = RPMB_REQ_AUTH_KEY_PROGRAM;
	else if (strcmp(cfg.cmd, "read-counter") == 0)
		cfg.opt = RPMB_REQ_READ_WRITE_CNTR;
	else if (strcmp(cfg.cmd, "write-data") == 0)
		cfg.opt = RPMB_REQ_AUTH_DATA_WRITE;
	else if (strcmp(cfg.cmd, "read-data") == 0)
		cfg.opt = RPMB_REQ_AUTH_DATA_READ;
	else if (strcmp(cfg.cmd, "write-config") == 0)
		cfg.opt = RPMB_REQ_AUTH_DCB_WRITE;
	else if (strcmp(cfg.cmd, "read-config") == 0)
		cfg.opt = RPMB_REQ_AUTH_DCB_READ;
	else {
		fprintf(stderr, "Invalid option %s for rpmb command\n", cfg.cmd);
		return -1;
	}
	
	/* input file/data processing */
	if (cfg.opt == RPMB_REQ_AUTH_DCB_WRITE || 
	    cfg.opt == RPMB_REQ_AUTH_DATA_WRITE ||
	    cfg.opt == RPMB_REQ_AUTH_KEY_PROGRAM)
	{
		key_buf = read_rpmb_key(cfg.key, cfg.keyfile, &key_size);
		if (key_buf == NULL) {
			fprintf(stderr, "Failed to read key\n");
			return -1;
		}
	
		if (key_size > 223 || key_size <= 0) {
			fprintf(stderr, "Invalid key size %d, valid input 1 to 223\n",
			key_size);
			return -1;
		}

		if (cfg.opt == RPMB_REQ_AUTH_DCB_WRITE ||
		    cfg.opt == RPMB_REQ_AUTH_DATA_WRITE) {
			if (cfg.msg != NULL) {
				msg_size = strlen(cfg.msg);
				msg_buf = (unsigned char *)malloc(msg_size);
				memcpy(msg_buf, cfg.msg, msg_size);
			} else {
				err = read_file(cfg.msgfile, &msg_buf, &msg_size);
				if (err || msg_size <= 0) {
					fprintf(stderr, "Failed to read file %s\n",
						cfg.msgfile);
					return -1;
				}
			}
		}
	}
	
	switch (cfg.opt) {
		case RPMB_REQ_READ_WRITE_CNTR:
			err = rpmb_read_write_counter(hdl, cfg.target, &write_cntr);
			if (err == 0)
				printf("Write Counter is: %u\n", write_cntr);
			break;
	
		case RPMB_REQ_AUTH_DCB_READ:
			write_cntr = rpmb_read_config_block(hdl, &msg_buf);
			if (msg_buf == NULL) {
				fprintf(stderr, "failed read config blk\n");
				return -1;
			}

			/* no output file is given, print the data on stdout */
			if (cfg.msgfile == 0) {
				struct rpmb_config_block_t *cfg =
						(struct rpmb_config_block_t *)msg_buf;
				printf("Boot Partition Protection is %s\n",
					((cfg->bp_enable & 0x1)  ? "Enabled" : "Disabled"));
				printf("Boot Partition 1 is %s\n",
					((cfg->bp_lock & 0x2) ? "Locked" : "Unlocked"));
				printf("Boot Partition 0 is %s\n",
					((cfg->bp_lock & 0x1) ? "Locked" : "Unlocked"));
			} else {
				printf("Saving received config data to %s file\n", cfg.msgfile);
				write_file(msg_buf, sizeof(struct rpmb_config_block_t), NULL,
					   cfg.msgfile, NULL);
			}
			err = (write_cntr == 0);
			break;
	
		case RPMB_REQ_AUTH_DATA_READ:
			/* check if requested data is beyond what target supports */
			msg_size = cfg.blocks * 512;
			if (invalid_xfer_size(cfg.blocks, regs.total_size)) {
				fprintf(stderr, "invalid transfer size %d \n",
					msg_size);
				break;
			}
			err = rpmb_auth_data_read(hdl, cfg.target,
						  cfg.address, &msg_buf,
						  cfg.blocks,
						  (regs.access_size + 1));
			if (err > 0 && msg_buf != NULL) {
				printf("Writing %d bytes to file %s\n",
					err * 512, cfg.msgfile);
				write_file(msg_buf, err * 512, NULL,
					   cfg.msgfile, NULL);
			}
			break;
	
		case RPMB_REQ_AUTH_DATA_WRITE:
			if (invalid_xfer_size(cfg.blocks, regs.total_size) || 
			    (cfg.blocks * 512) > msg_size) {
				fprintf(stderr, "invalid transfer size %d\n", 
					cfg.blocks * 512);
				break;
			} else if ((cfg.blocks * 512) < msg_size) {
				msg_size = cfg.blocks * 512;
			}
			err = rpmb_auth_data_write(hdl, cfg.target,
						   cfg.address,
						  ((regs.access_size + 1) * 512),
						   msg_buf, msg_size,
						   key_buf, key_size);

			/* print whatever extent of data written to target */
			printf("Written %d sectors out of %d @target(%d):0x%x\n",
				err/512, msg_size/512, cfg.target, cfg.address);
			break;

		case RPMB_REQ_AUTH_DCB_WRITE:
			err = rpmb_write_config_block(hdl, msg_buf,
						      key_buf, key_size);
			break;
	
		case RPMB_REQ_AUTH_KEY_PROGRAM:
			err = rpmb_program_auth_key(hdl, cfg.target,
						    key_buf, key_size);
			break;
		default:
			break;
	}

	return err;
}
