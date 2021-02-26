#ifndef __CLEANUP_H
#define __CLEANUP_H

#define __cleanup__(fn) __attribute__((cleanup(fn)))

#define DECLARE_CLEANUP_FUNC(name, type) \
	void name(type *__p)

#define DEFINE_CLEANUP_FUNC(name, type, free_fn)\
DECLARE_CLEANUP_FUNC(name, type)		\
{						\
	if (*__p)				\
		free_fn(*__p);			\
}

DECLARE_CLEANUP_FUNC(cleanup_charp, char *);
DECLARE_CLEANUP_FUNC(cleanup_fd, int);

#endif
