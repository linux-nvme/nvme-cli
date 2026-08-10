// SPDX-License-Identifier: LGPL-2.1-or-later
/**
 * This file is part of libnvme.
 * Copyright (c) 2025 Daniel Wagner, SUSE LLC
 */

#include <algorithm>
#include <libnvme.h>

static int minmax_test()
{
	/*
	 * Ensure libnvme doesn't spoil the namespace, e.g. by exposing a
	 * min/max macro.
	 */
	return !(std::min(1, 2) == 1 && std::max(1, 2) == 2);
}

int main(int argc, char *argv[])
{
	return minmax_test();
}
