#include "cleanup.h"
#include <stdlib.h>

DEFINE_CLEANUP_FUNC(cleanup_charp, char *, free);
