// SPDX-License-Identifier: GPL-2.0-only
#include "cleanup.h"
#include "types.h"
#include "nvme.h"
#include "sighdl.h"
#include "delay.h"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <math.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#define NVME_OUT "nvme.out"

int delay_set_stdout_file(struct delay_args *args)
{
	if (!args->time)
		return 0;

#ifdef HAVE_STDOUT_TO_SET
	args->fp = open_memstream(&args->buf, &args->len);
	if (!args->fp) {
		fprintf(stderr, "Failed to open memstream: %s\n",
			strerror(errno));
		return -errno;
	}
	args->stdout = stdout;
	stdout = args->fp;
#else /* HAVE_STDOUT_TO_SET */
	if (!freopen(NVME_OUT, "w", stdout)) {
		perror("freopen");
		return -errno;
	}
#endif /* HAVE_STDOUT_TO_SET */

	return 0;
}

#ifdef HAVE_STDOUT_TO_SET
static int get_file_line(char *buf)
{
	int line = 0;
	int len = 0;

	if (!buf)
		return line;

	while (len++ < strlen(buf)) {
		if (!buf[len])
			break;
		if (buf[len] == '\n')
			line++;
	}

	return line;
}
#else /* HAVE_STDOUT_TO_SET */
static char *read_file(const char *file, int *line, struct delay_args *args)
{
	_cleanup_file_ FILE *fd = fopen(file, "r");

	_cleanup_free_ char *str = NULL;
	struct stat st;
	int len = 0;
	char *buf;

	if (!file || !line || !fd || stat(file, &st))
		return NULL;

	*line = 0;

	str = malloc(args->col + 1);
	if (!str)
		return NULL;

	buf = malloc(st.st_size + 1);
	if (!buf)
		return NULL;

	while (fgets(str, args->col, fd)) {
		len += sprintf(&buf[len], "%s", str);
		(*line)++;
	}

	if (len)
		return buf;

	return NULL;
}
#endif /* HAVE_STDOUT_TO_SET */

static bool get_window_size(int fd, struct delay_args *args)
{
	struct winsize ws;

	if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
		return false;

	args->row = ws.ws_row;
	args->col = ws.ws_col;

	return true;
}

static bool delay_compare(struct delay_args *args, char **prev_buf, char **buf)
{
	if (args->last_index != args->index || args->last_row != args->row ||
	    args->last_col != args->col)
		args->changed = true;
	else
		args->changed = false;

	args->last_index = args->index;
	args->last_row = args->row;
	args->last_col = args->col;

	if (args->changed || !args->copy)
		return true;

	*prev_buf = strndup(args->copy, args->copy_len);
	if (!*prev_buf || args->len != args->copy_len)
		return true;

	return !!memcmp(*buf, *prev_buf, args->len);
}

static bool delay_copy(struct delay_args *args, char *buf, int len)
{
	if (args->copy)
		free(args->copy);

	args->copy = strndup(buf, len);
	args->copy_len = len;

	return true;
}

static void print_buf(char *buf, int index, int row)
{
	int start = 0;
	int line = 0;
	int len = 0;

	if (!buf)
		return;

	while (len++ < strlen(buf)) {
		if (!buf[len])
			break;
		if (buf[len] == '\n') {
			line++;
			if (index == line)
				start = len + 1;
		}
		if (line == row + index)
			break;
	}

	printf("%.*s", len - start, &buf[start]);
}

static void print_line(int row, char *line)
{
	printf("\033[%d;1H", row);
	printf("\033[2K");
	printf("%s\n", line ? line : "");
}

static bool delay_print(struct delay_args *args, char *prev_buf, char *buf)
{
	char *line = NULL, *prev = NULL, *save = NULL, *psave = NULL;
	int row = 0;
	int err;

	if (args->changed || !prev_buf) {
		printf("\033[?25l");
		err = system("clear");
		if (err < 0)
			return false;
		print_buf(buf, args->index, args->row);
		return true;
	}

	if (buf) {
		while (*buf == '\n') {
			buf++;
			if (prev_buf && *prev_buf)
				prev_buf++;
			row++;
		}
		line = strtok_r(buf, "\n", &save);
		row++;
	}

	if (prev_buf)
		prev = strtok_r(prev_buf, "\n", &psave);

	for (; row < args->index + args->row; row++) {
		if (line && prev && !memcmp(line, prev, strlen(line))) {
			while (*save == '\n') {
				save++;
				if (*psave)
					psave++;
				row++;
				print_line(row, NULL);
			}
			line = strtok_r(NULL, "\n", &save);
			prev = strtok_r(NULL, "\n", &psave);
			continue;
		}
		if (line) {
			print_line(row, line);
			while (*save == '\n') {
				save++;
				if (prev && *psave)
					psave++;
				row++;
				print_line(row, NULL);
			}
			line = strtok_r(NULL, "\n", &save);
		}
		if (prev)
			prev = strtok_r(NULL, "\n", &psave);
	}

	return true;
}

static bool check_up(char *str, int index)
{
	static const char up[] = "\x1b[A";

	if (memcmp(str, up, sizeof(up) - 1) || !index)
		return false;

	return true;
}

static bool check_down(int line, char *str, int index, int row)
{
	static const char down[] = "\x1b[B";

	if (memcmp(str, down, sizeof(down) - 1) || index + row > line)
		return false;

	return true;
}

bool delay_handle(struct delay_args *args)
{
	_cleanup_free_ char *prev_buf = NULL;
	int fd = open(ctermid(NULL), O_RDWR);
	_cleanup_free_ char *cur_buf = NULL;
	_cleanup_free_ char *str = NULL;
	struct termios orgtty;
	struct termios curtty;
	sigset_t sigwinch_set;
	struct timespec ts;
	sigset_t orig_set;
	struct winsize ws;
	char *prev = NULL;
	double delay_f;
	double delay_i;
	int len = 0;
	fd_set fds;
	char buf;
	int err;
	int line;

	if (!args->time)
		return false;

	sigemptyset(&sigwinch_set);
	sigemptyset(&orig_set);
	sigaddset(&sigwinch_set, SIGWINCH);
	sigprocmask(SIG_SETMASK, &sigwinch_set, &orig_set);

	if (fd < 0)
		return false;

	tcgetattr(fd, &orgtty);
	curtty = orgtty;

	curtty.c_lflag &= ~(ECHO | ICANON);
	tcsetattr(fd, TCSAFLUSH, &curtty);

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	if (!get_window_size(fd, args) || !args->row || !args->col)
		return false;

#ifdef HAVE_STDOUT_TO_SET
	fclose(args->fp);
	cur_buf = strndup(args->buf, args->len);
	line = get_file_line(cur_buf);
	stdout = args->stdout;
	free(args->buf);
#else /* HAVE_STDOUT_TO_SET */
	if (!freopen("/dev/tty", "w", stdout)) {
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &orgtty);
		return false;
	}
	cur_buf = read_file(NVME_OUT, &line, args);
	if (!cur_buf)
		return false;
#endif /* HAVE_STDOUT_TO_SET */

	if (delay_compare(args, &prev_buf, &cur_buf)) {
		if (!delay_print(args, prev_buf, cur_buf) ||
		    !delay_copy(args, cur_buf, line)) {
			tcsetattr(fd, TCSAFLUSH, &orgtty);
			printf("\033[?25h\n");
			return false;
		}
	}

	delay_f = modf(args->time, &delay_i);
	ts.tv_sec = delay_i;
	ts.tv_nsec = delay_f * 1000000000;
	do {
		err = pselect(fd + 1, &fds, NULL, NULL, &ts, NULL);
		if (err <= 0) {
			if (err < 0 && errno == EINTR) {
				if (nvme_sigwinch_received) {
					if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
						return false;
					args->row = ws.ws_row;
					nvme_sigwinch_received = false;
					err = 0;
				}
			}
			break;
		}
		err = read(fd, &buf, sizeof(buf));
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
		if (check_up(str, args->index)) {
			args->index--;
			break;
		} else if (check_down(line, str, args->index, args->row)) {
			args->index++;
			break;
		}
	} while (err > 0);

	tcsetattr(fd, TCSAFLUSH, &orgtty);

	if (err < 0) {
		printf("\033[?25h\n");
		return false;
	}

	return true;
}
