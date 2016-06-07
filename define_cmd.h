#ifdef CREATE_CMD
#undef CREATE_CMD


#define __stringify_1(x...) #x
#define __stringify(x...)  __stringify_1(x)
#define __CMD_INCLUDE(cmd) __stringify(cmd.h)
#define CMD_INCLUDE(cmd) __CMD_INCLUDE(cmd)

#define CMD_HEADER_MULTI_READ

#include CMD_INCLUDE(CMD_INC_FILE)

#include "cmd_handler.h"

#undef CMD_HEADER_MULTI_READ

#define CREATE_CMD
#endif
