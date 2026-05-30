/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

int fabrics_discovery(const char *desc, int argc, char **argv, bool connect);
int fabrics_connect(const char *desc, int argc, char **argv);
int fabrics_disconnect(const char *desc, int argc, char **argv);
int fabrics_disconnect_all(const char *desc, int argc, char **argv);
int fabrics_config(const char *desc, int argc, char **argv);
int fabrics_dim(const char *desc, int argc, char **argv);
