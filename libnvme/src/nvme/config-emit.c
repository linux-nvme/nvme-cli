// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libnvme.
 * Copyright (c) 2026, Dell Technologies Inc. or its subsidiaries.
 *
 * Authors: Martin Belanger <Martin.Belanger@dell.com>
 */

/*
 * Builds an NVMe Fabrics configuration from a flat list of connections.
 *
 * Intended for configuration migration. Existing configurations are not
 * merged; installation fails if a configuration already exists.
 *
 * Input is validated before writing. The generated configuration is parsed
 * again before installation to ensure it can be read successfully.
 */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ccan/list/list.h>

#include <nvme/config.h>
#include <nvme/nvme-types-fabrics.h>

#include "cleanup.h"
#include "compiler-attributes.h"
#include "config-ini.h"
#include "lib.h"
#include "private.h"
#include "private-fabrics.h"

#define emit_err(ctx, fmt, ...) \
	libnvme_msg(ctx, LIBNVME_LOG_ERR, fmt "\n", ##__VA_ARGS__)

struct emit_conn {
	struct list_node entry;
	bool is_dc;
	char *transport;
	char *traddr;
	char *trsvcid;		/* NULL = unset */
	char *subsysnqn;	/* NULL = default discovery NQN, DC only */
	char *host_traddr;	/* NULL = unset */
	char *host_iface;	/* NULL = unset */
	struct libnvmf_params *params;	/* NULL = no parameters */
};

/* One output file containing a persona and its connections. */
struct emit_persona {
	struct list_node entry;
	char *hostnqn;			/* NULL on the default persona */
	char *hostid;
	char *hostsymname;
	struct list_head conns;	/* struct emit_conn */
};

struct libnvmf_config_emitter {
	struct libnvme_global_ctx *ctx;
	struct list_head personas;	/* struct emit_persona, first-appearance order */
};

__libnvme_public struct libnvmf_config_emitter *libnvmf_config_emit_new(
		struct libnvme_global_ctx *ctx)
{
	struct libnvmf_config_emitter *emitter;

	if (!ctx)
		return NULL;

	emitter = calloc(1, sizeof(*emitter));
	if (!emitter)
		return NULL;
	emitter->ctx = ctx;
	list_head_init(&emitter->personas);

	return emitter;
}

__libnvme_public void libnvmf_config_emit_free(
		struct libnvmf_config_emitter *emitter)
{
	struct emit_persona *p, *pnext;
	struct emit_conn *c, *cnext;

	if (!emitter)
		return;

	list_for_each_safe(&emitter->personas, p, pnext, entry) {
		list_for_each_safe(&p->conns, c, cnext, entry) {
			free(c->transport);
			free(c->traddr);
			free(c->trsvcid);
			free(c->subsysnqn);
			free(c->host_traddr);
			free(c->host_iface);
			libnvmf_params_free(c->params);
			free(c);
		}
		free(p->hostnqn);
		free(p->hostid);
		free(p->hostsymname);
		free(p);
	}
	free(emitter);
}

static struct emit_persona *persona_for(struct libnvmf_config_emitter *emitter,
					const char *hostnqn, const char *hostid)
{
	struct emit_persona *p;

	list_for_each(&emitter->personas, p, entry) {
		if (streq0(p->hostnqn, hostnqn) &&
		    streq0(p->hostid, hostid))
			return p;
	}

	p = calloc(1, sizeof(*p));
	if (!p)
		return NULL;
	p->hostnqn = hostnqn ? strdup(hostnqn) : NULL;
	p->hostid = hostid ? strdup(hostid) : NULL;
	if ((hostnqn && !p->hostnqn) || (hostid && !p->hostid)) {
		free(p->hostnqn);
		free(p->hostid);
		free(p);
		return NULL;
	}
	list_head_init(&p->conns);
	list_add_tail(&emitter->personas, &p->entry);

	return p;
}

/*
 * Validate persona identity.
 *
 * A host is identified by the (hostnqn, hostid) pair. A hostnqn cannot be
 * associated with multiple hostids, and a hostid cannot be associated with
 * multiple hostnqns. A hostid requires a hostnqn. Checked here so the
 * emitter never writes a tree its own reader would reject.
 */
static int check_persona_identity(struct libnvmf_config_emitter *emitter,
				  const char *hostnqn, const char *hostid)
{
	struct emit_persona *p;

	if (hostid && !hostnqn) {
		emit_err(emitter->ctx,
			 "config emit: hostid %s without a hostnqn", hostid);
		return -EINVAL;
	}

	list_for_each(&emitter->personas, p, entry) {
		if (hostnqn && p->hostnqn && !strcmp(hostnqn, p->hostnqn) &&
		    !streq0(hostid, p->hostid)) {
			emit_err(emitter->ctx,
				 "config emit: hostnqn %s used with two hostids",
				 hostnqn);
			return -EINVAL;
		}
		if (hostid && p->hostid && !strcmp(hostid, p->hostid) &&
		    !streq0(hostnqn, p->hostnqn)) {
			emit_err(emitter->ctx,
				 "config emit: hostid %s shared by two hostnqns",
				 hostid);
			return -EINVAL;
		}
	}

	return 0;
}

__libnvme_public int libnvmf_config_emit_add(
		struct libnvmf_config_emitter *emitter, bool is_dc,
		const char *transport, const char *traddr,
		const char *trsvcid, const char *subsysnqn,
		const char *host_traddr, const char *host_iface,
		const char *hostnqn, const char *hostid,
		const struct libnvmf_params *params, const char *hostsymname)
{
	struct emit_persona *persona;
	struct emit_conn *conn;
	int ret;

	if (!emitter)
		return -EINVAL;

	if (!transport || !traddr) {
		emit_err(emitter->ctx,
			 "config emit: transport and traddr are required");
		return -EINVAL;
	}
	if (!is_dc && !subsysnqn) {
		emit_err(emitter->ctx,
			 "config emit: an I/O controller requires a subsysnqn");
		return -EINVAL;
	}

	ret = check_persona_identity(emitter, hostnqn, hostid);
	if (ret)
		return ret;

	persona = persona_for(emitter, hostnqn, hostid);
	if (!persona)
		return -ENOMEM;

	if (hostsymname) {
		if (persona->hostsymname &&
		    strcmp(persona->hostsymname, hostsymname)) {
			emit_err(emitter->ctx,
				 "config emit: conflicting hostsymname '%s' for persona %s",
				 hostsymname, persona->hostnqn ?
					      persona->hostnqn : "(default)");
			return -EINVAL;
		}
		if (!persona->hostsymname) {
			persona->hostsymname = strdup(hostsymname);
			if (!persona->hostsymname)
				return -ENOMEM;
		}
	}

	conn = calloc(1, sizeof(*conn));
	if (!conn)
		return -ENOMEM;
	conn->is_dc = is_dc;
	conn->transport = strdup(transport);
	conn->traddr = strdup(traddr);
	conn->trsvcid = xstrdup(trsvcid);
	conn->subsysnqn = xstrdup(subsysnqn);
	conn->host_traddr = xstrdup(host_traddr);
	conn->host_iface = xstrdup(host_iface);
	if (params)
		conn->params = libnvmf_params_dup(params);
	if (!conn->transport || !conn->traddr ||
	    (trsvcid && !conn->trsvcid) || (subsysnqn && !conn->subsysnqn) ||
	    (host_traddr && !conn->host_traddr) ||
	    (host_iface && !conn->host_iface) ||
	    (params && !conn->params)) {
		free(conn->transport);
		free(conn->traddr);
		free(conn->trsvcid);
		free(conn->subsysnqn);
		free(conn->host_traddr);
		free(conn->host_iface);
		libnvmf_params_free(conn->params);
		free(conn);
		return -ENOMEM;
	}

	list_add_tail(&persona->conns, &conn->entry);

	return 0;
}

static void write_param(const char *key, const char *value, void *user_data)
{
	FILE *fp = user_data;

	if (*value)
		fprintf(fp, "%s = %s\n", key, value);
	else
		fprintf(fp, "%s =\n", key);
}

static void write_conn(FILE *fp, const struct emit_conn *conn)
{
	if (conn->is_dc) {
		fprintf(fp, "[Discovery Controller]\n");
		/* Omit the default well-known discovery NQN. */
		if (conn->subsysnqn &&
		    strcmp(conn->subsysnqn, NVME_DISC_SUBSYS_NAME))
			fprintf(fp, "nqn = %s\n", conn->subsysnqn);
	} else {
		fprintf(fp, "[Subsystem]\n");
		fprintf(fp, "nqn = %s\n", conn->subsysnqn);
	}

	if (conn->params)
		libnvmf_params_for_each(conn->params, write_param, fp);

	fprintf(fp, "controller = transport=%s;traddr=%s",
		conn->transport, conn->traddr);
	if (conn->trsvcid)
		fprintf(fp, ";trsvcid=%s", conn->trsvcid);
	if (conn->host_traddr)
		fprintf(fp, ";host-traddr=%s", conn->host_traddr);
	if (conn->host_iface)
		fprintf(fp, ";host-iface=%s", conn->host_iface);
	fprintf(fp, "\n");
}

static void write_persona(FILE *fp, const struct emit_persona *persona)
{
	const struct emit_conn *conn;
	bool first = true;

	if (persona->hostnqn || persona->hostid || persona->hostsymname) {
		fprintf(fp, "[Host]\n");
		if (persona->hostnqn)
			fprintf(fp, "hostnqn = %s\n", persona->hostnqn);
		if (persona->hostid)
			fprintf(fp, "hostid = %s\n", persona->hostid);
		if (persona->hostsymname)
			fprintf(fp, "hostsymname = %s\n", persona->hostsymname);
		first = false;
	}

	list_for_each(&persona->conns, conn, entry) {
		if (!first)
			fprintf(fp, "\n");
		write_conn(fp, conn);
		first = false;
	}
}

/*
 * Write @persona to a temporary file and validate it by parsing it.
 *
 * On success, *@tmp_out receives the temporary file path. The caller is
 * responsible for renaming it to @final. On failure, the temporary file
 * is removed.
 */
static int emit_tmpfile(struct libnvme_global_ctx *ctx, const char *final,
			const struct emit_persona *persona, char **tmp_out)
{
	struct libnvmf_conf_file *raw;
	char *tmp;
	FILE *fp;
	int fd, ret;

	if (asprintf(&tmp, "%s.XXXXXX", final) < 0)
		return -ENOMEM;

	fd = libnvmf_mkstemp(tmp);
	if (fd < 0) {
		ret = fd;
		goto err_free;
	}
	if (fchmod(fd, 0644) < 0) {
		ret = -errno;
		close(fd);
		goto err_unlink;
	}
	fp = fdopen(fd, "w");
	if (!fp) {
		ret = -errno;
		close(fd);
		goto err_unlink;
	}

	write_persona(fp, persona);

	if (fflush(fp) != 0 || ferror(fp)) {
		fclose(fp);
		ret = -EIO;
		goto err_unlink;
	}
	if (fsync(fileno(fp)) != 0) {
		ret = -errno;
		fclose(fp);
		goto err_unlink;
	}
	if (fclose(fp) != 0) {
		ret = -errno;
		goto err_unlink;
	}

	ret = libnvmf_conf_file_parse(ctx, tmp, &raw);
	if (ret) {
		emit_err(ctx, "config emit: wrote an unreadable file");
		goto err_unlink;
	}
	libnvmf_conf_file_free(raw);

	*tmp_out = tmp;

	return 0;

err_unlink:
	unlink(tmp);
err_free:
	free(tmp);

	return ret;
}

/*
 * A configuration exists if the main file exists or the drop-in directory
 * contains at least one .conf file. Installation is one-shot migration,
 * by design never a merge into what's already there.
 */
static int target_occupied(const char *file, const char *dropin_dir)
{
	struct dirent **entries;
	struct stat st;
	bool occupied;
	int n;

	if (stat(file, &st) == 0)
		return -EEXIST;
	if (errno != ENOENT)
		return -errno;

	n = scandir(dropin_dir, &entries, libnvmf_conf_dropin_filter,
		    alphasort);
	if (n < 0)
		return errno == ENOENT ? 0 : -errno;
	occupied = n > 0;
	while (n > 0)
		free(entries[--n]);
	free(entries);

	return occupied ? -EEXIST : 0;
}

/*
 * Generate a drop-in file name.
 *
 * The numeric prefix preserves persona order. The persona's identity lives
 * inside the file ([Host]), so the name itself carries no user-controlled
 * text -- nothing to sanitize, nothing that can collide.
 */
static char *dropin_name(const char *dropin_dir, unsigned int index)
{
	char *path;

	if (asprintf(&path, "%s/%03u-persona.conf", dropin_dir,
		     100 + index) < 0)
		return NULL;

	return path;
}

/* Temporary and final paths for one output file. */
struct outfile {
	char *tmp;
	char *final;
};

static void outfiles_free(struct outfile *out, size_t n, bool rollback)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (rollback) {
			/*
			 * Roll back a partial install: each entry was either
			 * already renamed into place (only @final exists) or
			 * never got that far (only @tmp exists). Removing
			 * both is safe -- whichever one isn't there just
			 * fails with a harmless ENOENT.
			 */
			unlink(out[i].final);
			unlink(out[i].tmp);
		}
		free(out[i].tmp);
		free(out[i].final);
	}
	free(out);
}

__libnvme_public int libnvmf_config_emit_install(
		struct libnvmf_config_emitter *emitter, const char *file,
		bool force)
{
	__cleanup_free char *ddir = NULL;
	struct emit_persona empty_main = { 0 };
	const struct emit_persona *persona, *def = NULL;
	struct outfile *out;
	unsigned int index = 0;
	bool made_ddir = false;
	size_t nout = 0, npersona = 0, i;
	int ret;

	if (!emitter)
		return -EINVAL;
	if (!file)
		file = CONFIG_MAIN_PATH;

	list_head_init(&empty_main.conns);

	if (asprintf(&ddir, "%s.d", file) < 0)
		return -ENOMEM;

	if (!force) {
		ret = target_occupied(file, ddir);
		if (ret) {
			if (ret == -EEXIST)
				emit_err(emitter->ctx,
					 "%s: a configuration already exists",
					 file);
			return ret;
		}
	}

	list_for_each(&emitter->personas, persona, entry)
		npersona++;

	/* Write named personas first. Write the main file last. */
	out = calloc(npersona + 1, sizeof(*out));
	if (!out)
		return -ENOMEM;

	list_for_each(&emitter->personas, persona, entry) {
		if (!persona->hostnqn && !persona->hostid) {
			def = persona;
			continue;
		}
		if (!made_ddir) {
			if (mkdir(ddir, 0755) < 0 && errno != EEXIST) {
				ret = -errno;
				goto rollback;
			}
			made_ddir = true;
		}
		out[nout].final = dropin_name(ddir, index++);
		if (!out[nout].final) {
			ret = -ENOMEM;
			goto rollback;
		}
		ret = emit_tmpfile(emitter->ctx, out[nout].final, persona,
				   &out[nout].tmp);
		if (ret) {
			/* emit_tmpfile removed its temp; free the final. */
			free(out[nout].final);
			out[nout].final = NULL;
			goto rollback;
		}
		nout++;
	}

	/*
	 * Write the main configuration file. If no default persona exists,
	 * write an empty main file.
	 */
	out[nout].final = strdup(file);
	if (!out[nout].final) {
		ret = -ENOMEM;
		goto rollback;
	}
	ret = emit_tmpfile(emitter->ctx, out[nout].final,
			   def ? def : &empty_main, &out[nout].tmp);
	if (ret) {
		free(out[nout].final);
		out[nout].final = NULL;
		goto rollback;
	}
	nout++;

	/* Install validated files. */
	for (i = 0; i < nout; i++) {
		if (rename(out[i].tmp, out[i].final) < 0) {
			ret = -errno;
			goto rollback;
		}
	}

	outfiles_free(out, nout, false);

	return 0;

rollback:
	/* out[0..nout-1] are complete; any partial slot was freed inline. */
	outfiles_free(out, nout, true);
	if (made_ddir)
		rmdir(ddir);	/* only succeeds if we left it empty */

	return ret;
}
