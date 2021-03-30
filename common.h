#ifndef _COMMON_H
#define _COMMON_H

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define min(x, y) ((x) > (y) ? (y) : (x))
#define max(x, y) ((x) > (y) ? (x) : (y))

#define __stringify_1(x...) #x
#define __stringify(x...)  __stringify_1(x)

#define container_of_const(ptr, type, member) ({	\
	typeof( ((const type *)0)->member ) *__mptr = (ptr);	\
	(const type *)( (const char *)__mptr - offsetof(type,member) );})
#define container_of(ptr, type, member) ({		\
	typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define STEAL_PTR(p) ({ typeof(p) __tmp = (p); (p) = NULL; __tmp; })

#endif
