// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Unit tests for src/plugin-loader.c with real modules, see
 * plugin-modules/meson.build. NVME_PLUGIN_DIR points to them.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ccan/array_size/array_size.h>

#include "plugin-loader.h"
#include "plugin-test-module.h"

static int test_rc;

static const char *const names[] = {
	"good", "with-dash", "misnamed", "stale", "noinit", "broken",
	"outside",
};
static int inits[ARRAY_SIZE(names)];

void plugin_test_init(const char *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		if (!strcmp(name, names[i]))
			inits[i]++;
	}
}

static int nr_inits(const char *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		if (!strcmp(name, names[i]))
			return inits[i];
	}
	return -1;
}

static void check(bool cond, const char *desc)
{
	if (!cond) {
		printf("ERROR: %s\n", desc);
		test_rc = 1;
	}
}

static char err[4096];

/* Runs @fn, what it writes to stderr ends up in err */
static void capture_stderr(void (*fn)(const char *), const char *arg)
{
	FILE *tmp = tmpfile();
	int saved;
	size_t n;

	err[0] = '\0';
	if (!tmp) {
		printf("ERROR: tmpfile: %s\n", strerror(errno));
		test_rc = 1;
		return;
	}
	fflush(stderr);
	saved = dup(STDERR_FILENO);
	dup2(fileno(tmp), STDERR_FILENO);

	fn(arg);

	fflush(stderr);
	dup2(saved, STDERR_FILENO);
	close(saved);
	fseek(tmp, 0, SEEK_SET);
	n = fread(err, 1, sizeof(err) - 1, tmp);
	err[n] = '\0';
	fclose(tmp);
}

static void load_all(const char *unused)
{
	(void)unused;
	nvme_load_plugins();
}

int main(void)
{
	const char *dir = getenv("NVME_PLUGIN_DIR");

	check(dir && !strcmp(nvme_plugin_dir(), dir),
	      "NVME_PLUGIN_DIR selects the module directory");

	capture_stderr(nvme_load_plugin, "good");
	check(nr_inits("good") == 1 && !err[0], "a module is initialized");

	capture_stderr(nvme_load_plugin, "good");
	check(nr_inits("good") == 1 && !err[0],
	      "a module is initialized once");

	capture_stderr(nvme_load_plugin, "missing");
	check(!err[0], "no module for a name is no error");

	capture_stderr(nvme_load_plugin, "../outside");
	check(nr_inits("outside") == 0 && !err[0],
	      "a name is not a path");
	capture_stderr(nvme_load_plugin, "");
	check(!err[0], "an empty name loads nothing");

	capture_stderr(nvme_load_plugin, "stale");
	check(nr_inits("stale") == 0 &&
	      strstr(err, "built for nvme 0.0-stale") != NULL,
	      "a module for another nvme is not initialized");

	capture_stderr(nvme_load_plugin, "noinit");
	check(strstr(err, "not a plugin of nvme") != NULL,
	      "a module without its init function is no plugin");

	capture_stderr(nvme_load_plugin, "misnamed");
	check(nr_inits("misnamed") == 0 && nr_inits("good") == 1 &&
	      strstr(err, "not a plugin of nvme") != NULL,
	      "the symbols of another plugin make no plugin");

	capture_stderr(nvme_load_plugin, "broken");
	check(nr_inits("broken") == 0 &&
	      strstr(err, "plugin_test_undefined") != NULL,
	      "a module with an unresolved symbol is not loaded");

	capture_stderr(load_all, NULL);
	check(nr_inits("good") == 1 && nr_inits("with-dash") == 1,
	      "loading all initializes the rest once, '-' in a name is '_'");
	check(nr_inits("stale") == 0 && nr_inits("broken") == 0 &&
	      nr_inits("outside") == 0,
	      "loading all skips the bad modules");

	capture_stderr(load_all, NULL);
	check(!err[0], "all modules are loaded once");

	return test_rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
