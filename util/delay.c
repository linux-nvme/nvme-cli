// SPDX-License-Identifier: GPL-2.0-only
#include "cleanup.h"
#include "types.h"
#include "nvme.h"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <math.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>

#define NVME_OUT "nvme.out"
#define NVME_PREV_OUT "nvme-prev.out"

int delay_set_stdout_file(void)
{
	if (!freopen(NVME_OUT, "w", stdout)) {
		perror("freopen");
		return -errno;
	}

	return 0;
}

static int get_file_line(const char *file)
{
	_cleanup_file_ FILE *fd = fopen(file, "r");

	_cleanup_free_ char *str = NULL;
	int len = STR_LEN;
	int line = 0;

	if (!file || !fd)
		return 0;

	str = malloc(len + 1);
	if (str) {
		while (fgets(str, len, fd))
			line++;
	}

	return line;
}

static bool get_window_size(int *row, int *col)
{
	struct winsize ws;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0)
		return false;

	*row = ws.ws_row;
	*col = ws.ws_col;

	return true;
}

static char *read_file(const char *file, size_t *len, int i, int row, int col)
{
	_cleanup_file_ FILE *fd = fopen(file, "r");
	_cleanup_free_ char *str = NULL;
	struct stat st;
	char *buf;
	int j = 0;

	if (!file || !len || !fd || stat(file, &st))
		return NULL;

	*len = 0;

	str = malloc(col + 1);
	if (!str)
		return NULL;

	buf = malloc(st.st_size + 1);
	if (!buf)
		return NULL;

	for (j = 0; j < i + row - 1; j++) {
		if (!fgets(str, col, fd))
			break;
		if (j >= i)
			*len += sprintf(&buf[*len], "%s", str);
	}

	if (*len)
		return buf;

	return NULL;
}

static bool delay_compare(int i, int row, int col)
{
	_cleanup_free_ char *prev_buf = NULL;
	_cleanup_free_ char *buf = NULL;
	bool changed = false;
	static int last_row;
	static int last_col;
	static int last_i;
	size_t prev_len;
	struct stat st;
	size_t len;

	if (last_i != i || last_row != row || last_col != col)
		changed = true;

	last_i = i;
	last_row = row;
	last_col = col;

	if (changed || stat(NVME_PREV_OUT, &st))
		return true;

	buf = read_file(NVME_OUT, &len, i, row, col);
	if (!buf)
		return true;

	prev_buf = read_file(NVME_PREV_OUT, &prev_len, i, row, col);
	if (!prev_buf || len != prev_len)
		return true;

	return !!memcmp(buf, prev_buf, len);
}

static bool delay_copy(void)
{
	_cleanup_free_ char *cmd = NULL;
	int err;

	if (asprintf(&cmd, "cp %s %s", NVME_OUT, NVME_PREV_OUT) < 0)
		return false;

	err = system(cmd);
	if (err < 0)
		return false;

	return true;
}

static bool delay_print(int i, int row, int col)
{
	_cleanup_free_ char *buf = NULL;
	size_t len;
	int err;

	buf = read_file(NVME_OUT, &len, i, row, col);
	if (!buf)
		return false;

	err = system("clear");
	if (err < 0)
		return false;

	printf("%s", buf);

	return true;
}

static bool check_up(char *str, int i)
{
	static const char up[] = "\x1b[A";

	if (memcmp(str, up, sizeof(up) - 1) || !i)
		return false;

	return true;
}

static bool check_down(char *str, int i, int row)
{
	static const char down[] = "\x1b[B";
	int line = get_file_line(NVME_OUT);

	if (memcmp(str, down, sizeof(down) - 1) || i + row >= line)
		return false;

	return true;
}

bool delay_handle(void)
{
	_cleanup_free_ char *str = NULL;
	struct termios orgtty;
	struct termios curtty;
	struct timespec ts;
	char *prev = NULL;
	double delay_f;
	double delay_i;
	static int row;
	static int col;
	static int i;
	fd_set fds;
	int len = 0;
	char buf;
	int err;

	tcgetattr(STDIN_FILENO, &orgtty);
	curtty = orgtty;

	curtty.c_lflag &= ~(ECHO | ICANON);
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &curtty);

	FD_ZERO(&fds);
	FD_SET(STDIN_FILENO, &fds);

	if (!freopen("/dev/tty", "w", stdout)) {
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &orgtty);
		return false;
	}

	if (!get_window_size(&row, &col) || !row || !col)
		return false;

	if (delay_compare(i, row, col)) {
		if (!delay_print(i, row, col) || !delay_copy()) {
			tcsetattr(STDIN_FILENO, TCSAFLUSH, &orgtty);
			return false;
		}
	}

	delay_f = modf(nvme_args.delay, &delay_i);
	ts.tv_sec = delay_i;
	ts.tv_nsec = delay_f * 1000000000;
	do {
		err = pselect(STDIN_FILENO + 1, &fds, NULL, NULL, &ts, NULL);
		if (err <= 0)
			break;
		err = read(STDIN_FILENO, &buf, sizeof(buf));
		if (err <= 0)
			break;
		len += err;
		str = malloc(len);
		if (!str)
			continue;
		if (prev && len > 1) {
			memcpy(str, prev, len - err);
			free(prev);
		}
		str[len - 1] = buf;
		prev = str;
		if (check_up(str, i)) {
			i--;
			break;
		} else if (check_down(str, i, row)) {
			i++;
			break;
		}
	} while (err > 0);

	tcsetattr(STDIN_FILENO, TCSAFLUSH, &orgtty);

	if (err < 0)
		return false;

	return true;
}

int delay_remove_file(void)
{
	struct stat st;

	if (!stat(NVME_OUT, &st) && remove(NVME_OUT))
		return -errno;

	if (!stat(NVME_PREV_OUT, &st) && remove(NVME_PREV_OUT))
		return -errno;

	return 0;
}
