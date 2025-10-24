/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2022 Solidigm.
 *
 * Authors: haro.panosyan@solidigm.com
 *          leonardo.da.cunha@solidigm.com
 */

int ocp_clear_fw_update_history(int argc, char **argv, struct command *acmd, struct plugin *plugin);

int ocp_clear_pcie_correctable_errors(int argc, char **argv, struct command *acmd,
					     struct plugin *plugin);

int get_ocp_error_counters(int argc, char **argv, struct command *acmd,
			    struct plugin *plugin);
