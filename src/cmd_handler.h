/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Stage 1
 *
 * Define function prototypes.
 */

#undef NAME
#define NAME(n, d, v)

#undef NAME_CORE
#define NAME_CORE(n, d, v)

#undef ENTRY
#define ENTRY(n, h, f, ...) \
static int f(int argc, char **argv, struct command *acmd, struct plugin *plugin);

#undef ENTRY_DEPRECATED
#define ENTRY_DEPRECATED(n, h, f, ...) \
static int f(int argc, char **argv, struct command *acmd, struct plugin *plugin);

#undef GL_ENT
#define GL_ENT(n, h, f, ...) \
int f(int argc, char **argv, struct command *acmd, struct plugin *plugin);

#undef COMMAND_LIST
#define COMMAND_LIST(args...) args

#undef PLUGIN
#define PLUGIN(name, cmds) cmds

#include CMD_INCLUDE(CMD_INC_FILE)

/*
 * Stage 2
 *
 * Define command structures.
 */

#undef NAME
#define NAME(n, d, v)

#undef NAME_CORE
#define NAME_CORE(n, d, v)

#undef ENTRY_W_ALIAS
#define ENTRY_W_ALIAS(n, h, f, a)	\
static struct command f ## _cmd = {	\
	.name = n, 			\
	.help = h, 			\
	.fn = f, 			\
	.alias = a, 			\
};

#undef ENTRY_WO_ALIAS
#define ENTRY_WO_ALIAS(n, h, f)		\
	ENTRY_W_ALIAS(n, h, f, NULL)

#undef ENTRY_SEL
#define ENTRY_SEL(n, h, f, a, CMD, ...) CMD

#undef ENTRY
#define ENTRY(...) 		\
	ENTRY_SEL(__VA_ARGS__, ENTRY_W_ALIAS, ENTRY_WO_ALIAS)(__VA_ARGS__)

#undef ENTRY_DEPRECATED_W_ALIAS
#define ENTRY_DEPRECATED_W_ALIAS(n, h, f, a)	\
static struct command f ## _cmd = {	\
	.name = n, 			\
	.help = h, 			\
	.fn = f, 			\
	.alias = a, 			\
	.deprecated = true,		\
};

#undef ENTRY_DEPRECATED_WO_ALIAS
#define ENTRY_DEPRECATED_WO_ALIAS(n, h, f)		\
	ENTRY_DEPRECATED_W_ALIAS(n, h, f, NULL)

#undef ENTRY_DEPRECATED_SEL
#define ENTRY_DEPRECATED_SEL(n, h, f, a, CMD, ...) CMD

#undef ENTRY_DEPRECATED
#define ENTRY_DEPRECATED(...) 		\
	ENTRY_DEPRECATED_SEL(__VA_ARGS__, ENTRY_DEPRECATED_W_ALIAS, ENTRY_DEPRECATED_WO_ALIAS)(__VA_ARGS__)

#undef GL_ENT
#define GL_ENT ENTRY

#undef COMMAND_LIST
#define COMMAND_LIST(args...) args

#undef PLUGIN
#define PLUGIN(name, cmds) cmds

#include CMD_INCLUDE(CMD_INC_FILE)

/*
 * Stage 3
 *
 * Generate list of commands for the plugin.
 */

#undef NAME
#define NAME(n, d, v)

#undef NAME_CORE
#define NAME_CORE(n, d, v)

#undef ENTRY
#define ENTRY(n, h, f, ...) &f ## _cmd,

#undef ENTRY_DEPRECATED
#define ENTRY_DEPRECATED(n, h, f, ...) &f ## _cmd,

#undef GL_ENT
#define GL_ENT ENTRY

#undef COMMAND_LIST
#define COMMAND_LIST(args...)	\
static struct command *commands[] = {	\
	args				\
	NULL,				\
};

#undef PLUGIN
#define PLUGIN(name, cmds) cmds

#include CMD_INCLUDE(CMD_INC_FILE)

/*
 * Stage 4
 *
 * Define and register plugin
 */

#undef NAME
#define NAME(n, d, v) .name = n, .desc = d, .version = v,

#undef NAME_CORE
#define NAME_CORE(n, d, v) .name = n, .desc = d, .version = v, .core = true,

#undef COMMAND_LIST
#define COMMAND_LIST(args...)

#undef PLUGIN
#define PLUGIN(name, cmds)				\
static struct plugin plugin = {				\
	name						\
	.commands = commands				\
}; 							\
							\
static void init(void) __attribute__((constructor)); 	\
static void init(void)					\
{							\
	register_extension(&plugin);			\
}

#include CMD_INCLUDE(CMD_INC_FILE)
