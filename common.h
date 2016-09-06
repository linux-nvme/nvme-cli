#ifndef _COMMON_H
#define _COMMON_H

#define offsetof(x, y)	__builtin_offsetof(x, y)

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#endif
