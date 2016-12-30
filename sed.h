#ifndef _UAPI_SED_H
#define _UAPI_SED_H

#include <linux/types.h>
#include "plugin.h"

extern int sed_save(int argc, char **argv, struct command *cmd, struct plugin *plugin);
extern int sed_lock_unlock(int argc, char **argv, struct command *cmd, struct plugin *plugin);
extern int sed_ownership(int argc, char **argv, struct command *cmd, struct plugin *plugin);
extern int sed_activatelsp(int argc, char **argv, struct command *cmd, struct plugin *plugin);
extern int sed_reverttper(int argc, char **argv, struct command *cmd, struct plugin *plugin);
extern int sed_setuplr(int argc, char **argv, struct command *cmd, struct plugin *plugin);
extern int sed_add_usr_to_lr(int argc, char **argv, struct command *cmd, struct plugin *plugin);
extern int sed_shadowmbr(int argc, char **argv, struct command *cmd,  struct plugin *plugin);
extern int sed_setpw(int argc, char **argv, struct command *cmd, struct plugin *plugin);
extern int sed_enable_user(int argc, char **argv, struct command *cmd, struct plugin *plugin);
extern int sed_erase_lr(int argc, char **argv, struct command *cmd, struct plugin *plugin);
extern int sed_secure_erase_lr(int argc, char **argv, struct command *cmd, struct plugin *plugin);


static int _sed_save(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return sed_save(argc, argv, cmd, plugin);
}
static int _sed_lock_unlock(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return sed_lock_unlock(argc, argv, cmd, plugin);
}
static int _sed_ownership(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return sed_ownership(argc, argv, cmd, plugin);
}
static int _sed_activatelsp(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return sed_activatelsp(argc, argv, cmd, plugin);
}
static int _sed_reverttper(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return sed_reverttper(argc, argv, cmd, plugin);
}
static int _sed_setuplr(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return sed_setuplr(argc, argv, cmd, plugin);
}
static int _sed_add_usr_to_lr(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return sed_add_usr_to_lr(argc, argv, cmd, plugin);
}
static int _sed_shadowmbr(int argc, char **argv, struct command *cmd,  struct plugin *plugin)
{
	return sed_shadowmbr(argc, argv, cmd, plugin);
}
static int _sed_setpw(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return sed_setpw(argc, argv, cmd, plugin);
}
static int _sed_enable_user(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return sed_enable_user(argc, argv, cmd, plugin);
}
static int _sed_erase_lr(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return sed_erase_lr(argc, argv, cmd, plugin);
}
static int _sed_secure_erase_lr(int argc, char **argv, struct command *cmd, struct plugin *plugin)
{
	return sed_secure_erase_lr(argc, argv, cmd, plugin);
}



#endif
