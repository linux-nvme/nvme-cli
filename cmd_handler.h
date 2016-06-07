/*
 * Stage 1
 */

#undef ENTRY
#define ENTRY(n, h, f) \
static int f(int argc, char **argv, struct command *command, struct plugin *plugin);

#undef COMMAND_LIST
#define COMMAND_LIST(args...) args

#include CMD_INCLUDE(CMD_INC_FILE)

/*
 * Stage 2
 */

#undef ENTRY
#define ENTRY(n, h, f)			\
static struct command f ## _cmd = {	\
	.name = n, 			\
	.help = h, 			\
	.fn = f, 			\
};

#undef COMMAND_LIST
#define COMMAND_LIST(args...) args

#include CMD_INCLUDE(CMD_INC_FILE)

/*
 * Stage 3
 */

#undef ENTRY
#define ENTRY(n, h, f) &f ## _cmd,

#undef COMMAND_LIST
#define COMMAND_LIST(args...)	\
static struct command *commands[] = {	\
	args				\
	NULL,				\
};

#include CMD_INCLUDE(CMD_INC_FILE)
