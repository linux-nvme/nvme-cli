// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This file is part of nvme-cli.
 * Copyright (c) 2026 SUSE Software Solutions
 *
 * Authors: Daniel Wagner <dwagner@suse.de>
 */

/*
 * Run a fuzz target without libFuzzer, for the regular test suite: feed
 * it the seed corpus, then mutations of it for a while. The mutations
 * come from a fixed seed, so a run can be repeated. An input which
 * crashes the target is written to fuzz-crash-<target> first.
 *
 * Usage: fuzz-<target> <corpus-dir>
 * FUZZ_SECONDS sets the time for the mutations (default 2), FUZZ_SEED the
 * seed (default 1).
 */

#include <dirent.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define FUZZ_MAX_INPUT	4096
#define FUZZ_MAX_SEEDS	256

#include "fuzz.h"

/* a target need not have one */
int LLVMFuzzerInitialize(int *argc, char ***argv) __attribute__((weak));

static struct {
	uint8_t *data;
	size_t size;
} seeds[FUZZ_MAX_SEEDS];
static int nr_seeds;

static const char *target;
static uint8_t input[FUZZ_MAX_INPUT];
static size_t input_size;

static uint64_t rng_state;

static uint64_t rng(void)
{
	/* xorshift64 */
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

/* Keep the input which crashed the target */
static void crash(int sig)
{
	char path[256];
	FILE *f;

	snprintf(path, sizeof(path), "fuzz-crash-%s", target);
	f = fopen(path, "wb");
	if (f) {
		fwrite(input, 1, input_size, f);
		fclose(f);
	}
	signal(sig, SIG_DFL);
	raise(sig);
}

static void run(const uint8_t *data, size_t size)
{
	if (size > FUZZ_MAX_INPUT)
		size = FUZZ_MAX_INPUT;
	memcpy(input, data, size);
	input_size = size;
	LLVMFuzzerTestOneInput(input, input_size);
}

static void load_seeds(const char *dir)
{
	struct dirent *e;
	char path[4096];
	DIR *d = opendir(dir);

	if (!d)
		return;

	while ((e = readdir(d)) && nr_seeds < FUZZ_MAX_SEEDS) {
		FILE *f;
		size_t n;

		if (e->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		f = fopen(path, "rb");
		if (!f)
			continue;
		seeds[nr_seeds].data = malloc(FUZZ_MAX_INPUT);
		if (!seeds[nr_seeds].data) {
			fclose(f);
			break;
		}
		n = fread(seeds[nr_seeds].data, 1, FUZZ_MAX_INPUT, f);
		fclose(f);
		seeds[nr_seeds].size = n;
		nr_seeds++;
	}
	closedir(d);
}

/* The bytes which separate or mark things for the parsers */
static const uint8_t special[] = {
	'\0', '-', '=', ',', '.', '[', ']', '\n', '#', ' ', '0', 'x', 'K', 'i',
	0x1b, 0x7f, 0xff,
};

static void mutate(uint8_t *buf, size_t *size)
{
	int n = 1 + rng() % 8;

	while (n--) {
		size_t pos = *size ? rng() % *size : 0;

		switch (rng() % 7) {
		case 0:	/* flip a bit */
			if (*size)
				buf[pos] ^= 1 << (rng() % 8);
			break;
		case 1:	/* set a random byte */
			if (*size)
				buf[pos] = rng();
			break;
		case 2:	/* insert a special byte */
			if (*size < FUZZ_MAX_INPUT) {
				memmove(buf + pos + 1, buf + pos, *size - pos);
				buf[pos] = special[rng() % sizeof(special)];
				(*size)++;
			}
			break;
		case 3:	/* delete a byte */
			if (*size) {
				memmove(buf + pos, buf + pos + 1,
					*size - pos - 1);
				(*size)--;
			}
			break;
		case 4: {	/* duplicate a chunk */
			size_t len = *size ? 1 + rng() % (*size - pos) : 0;

			if (*size + len <= FUZZ_MAX_INPUT) {
				memmove(buf + pos + len, buf + pos,
					*size - pos);
				*size += len;
			}
			break;
		}
		case 5: {	/* splice in a part of another seed */
			int s = rng() % nr_seeds;
			size_t len = seeds[s].size ? rng() % seeds[s].size : 0;

			if (pos + len <= FUZZ_MAX_INPUT) {
				memcpy(buf + pos, seeds[s].data, len);
				if (pos + len > *size)
					*size = pos + len;
			}
			break;
		}
		case 6:	/* cut off the end */
			*size = pos;
			break;
		}
	}
}

int main(int argc, char **argv)
{
	const char *secs = getenv("FUZZ_SECONDS");
	const char *seed = getenv("FUZZ_SEED");
	unsigned long runs = 0;
	uint8_t buf[FUZZ_MAX_INPUT];
	time_t end;
	int i, out;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <corpus-dir>\n", argv[0]);
		return 2;
	}
	target = strrchr(argv[0], '/') ? strrchr(argv[0], '/') + 1 : argv[0];
	if (!strncmp(target, "fuzz-", 5))
		target += 5;

	rng_state = seed ? strtoull(seed, NULL, 0) : 1;
	if (!rng_state)
		rng_state = 1;
	load_seeds(argv[1]);
	if (!nr_seeds) {
		fprintf(stderr, "no seeds in %s\n", argv[1]);
		return 2;
	}

	signal(SIGSEGV, crash);
	signal(SIGABRT, crash);
	signal(SIGBUS, crash);
	signal(SIGFPE, crash);
	signal(SIGILL, crash);

	if (LLVMFuzzerInitialize)
		LLVMFuzzerInitialize(&argc, &argv);

	/* the target may print, keep stdout for the summary */
	fflush(stdout);
	out = dup(STDOUT_FILENO);
	if (!freopen("/dev/null", "w", stdout) ||
	    !freopen("/dev/null", "w", stderr))
		return 2;

	for (i = 0; i < nr_seeds; i++)
		run(seeds[i].data, seeds[i].size);

	end = time(NULL) + (secs ? strtol(secs, NULL, 0) : 2);
	while (time(NULL) < end) {
		int s = rng() % nr_seeds;
		size_t size = seeds[s].size;

		memcpy(buf, seeds[s].data, size);
		mutate(buf, &size);
		run(buf, size);
		runs++;
	}

	if (out >= 0) {
		dprintf(out, "%s: %d seeds, %lu mutations, seed %s\n", target,
			nr_seeds, runs, seed ? seed : "1");
		close(out);
	}

	for (i = 0; i < nr_seeds; i++)
		free(seeds[i].data);

	return 0;
}
