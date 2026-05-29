/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _FABRICS_H
#define _FABRICS_H

int fabrics_discovery(const char *desc, int argc, char **argv, bool connect);
int fabrics_connect(const char *desc, int argc, char **argv);
int fabrics_disconnect(const char *desc, int argc, char **argv);
int fabrics_disconnect_all(const char *desc, int argc, char **argv);
int fabrics_registry_list(const char *desc, int argc, char **argv);
int fabrics_registry_retrieve(const char *desc, int argc, char **argv);
int fabrics_registry_update(const char *desc, int argc, char **argv);
int fabrics_registry_delete(const char *desc, int argc, char **argv);
int fabrics_config(const char *desc, int argc, char **argv);
int fabrics_dim(const char *desc, int argc, char **argv);


#endif
