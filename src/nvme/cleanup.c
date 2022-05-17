// SPDX-License-Identifier: LGPL-2.1-or-later
#include <stdlib.h>
#include "cleanup.h"

DEFINE_CLEANUP_FUNC(cleanup_charp, char *, free);
