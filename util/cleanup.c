#include <stdlib.h>
#include <unistd.h>
#include "cleanup.h"

DEFINE_CLEANUP_FUNC(cleanup_charp, char *, free);
DEFINE_CLEANUP_FUNC(cleanup_fd, int, close);
