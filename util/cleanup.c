// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdlib.h>
#include "cleanup.h"

DEFINE_CLEANUP_FUNC(cleanup_charp, char *, free);
