/*
 * Copyright (C) 2016 prpl Foundation
 * Written by Felix Fietkau <nbd@nbd.name>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/wait.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <limits.h>
#include <fcntl.h>
#include <ctype.h>
#include "scapi_json.h"

static int run_command(struct blob_attr *data, int argc, int fd)
{
	struct blob_attr *cur;
	char **argv;
	int pid, rem;
	int i;

	pid = fork();
	if (pid) {
		close(fd);
		return pid;
	}

	i = 0;
	argv = calloc(argc + 1, sizeof(char *));
	blobmsg_for_each_attr(cur, data, rem) {
		argv[i++] = blobmsg_get_string(cur);
	}

	for (i = 0; i <= 2; i++) {
		if (fd == i)
			continue;

		close(i);
		dup2(fd, i);
	}

	execvp(argv[0], argv);
	exit(255);
}

static uint64_t gettime(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t) ts.tv_sec + (uint64_t) ts.tv_nsec / 1000000UL;
}

static void shell_read_data(struct blob_buf *b, int rfd, uint64_t timeout,
			    unsigned int maxlen)
{
	struct pollfd pfd = {
		.fd = rfd,
		.events = POLLIN | POLLERR | POLLHUP,
	};
	char *buf = blobmsg_alloc_string_buffer(b, "value", 256);
	uint64_t cur;
	int len = 0;

	while ((cur = gettime()) < timeout) {
		int cur_max;
		int cur_len;

		cur_max = maxlen - len;
		if (cur_max <= 0)
			break;

		if (cur_max > 255)
			cur_max = 255;

		cur_len = read(rfd, buf + len, cur_max);
		if (!cur_len)
			break;

		if (cur_len < 0) {
			if (errno == EINTR)
				continue;
			else if (errno == EAGAIN)
				cur_len = 0;
			else
				break;
		}

		len += cur_len;
		buf = blobmsg_realloc_string_buffer(b, len + 256);
		poll(&pfd, 1, timeout - cur);
	}

	while (len > 0 && isspace(buf[len - 1]))
		len--;

	buf[len] = 0;

	blobmsg_add_string_buffer(b);
}

static int shell_param_get(struct sj_session *ctx, struct blob_attr *data, struct blob_buf *buf)
{
	enum {
		DATA_COMMAND,
		DATA_MAXLEN,
		DATA_TIMEOUT,
		__DATA_MAX
	};
	static const struct blobmsg_policy policy[__DATA_MAX] = {
		[DATA_COMMAND] = { "command", BLOBMSG_TYPE_ARRAY },
		[DATA_MAXLEN] = { "maxlen", BLOBMSG_TYPE_INT32 },
		[DATA_TIMEOUT] = { "timeout", BLOBMSG_TYPE_INT32 },
	};
	struct blob_attr *tb[__DATA_MAX];
	struct blob_attr *cur;
	unsigned int timeout = 30 * 1000;
	unsigned int maxlen = INT_MAX;
	uint64_t end;
	int fds[2];
	int argc;
	int pid;
	int ret = 0;

	blobmsg_parse(policy, __DATA_MAX, tb, blobmsg_data(data), blobmsg_data_len(data));

	if (!tb[DATA_COMMAND])
		return SC_ERR_INVALID_ARGUMENT;

	if ((cur = tb[DATA_TIMEOUT]) != NULL)
		timeout = blobmsg_get_u32(cur);

	if ((cur = tb[DATA_MAXLEN]) != NULL)
		maxlen = blobmsg_get_u32(cur);

	argc = blobmsg_check_array(tb[DATA_COMMAND], BLOBMSG_TYPE_STRING);
	if (argc < 1)
		return SC_ERR_INVALID_ARGUMENT;

	if (pipe(fds) < 0)
		return SC_ERR_UNKNOWN;

	pid = run_command(tb[DATA_COMMAND], argc, fds[1]);
	if (pid < 0) {
		ret = SC_ERR_UNKNOWN;
		goto out;
	}

	end = gettime() + timeout;
	shell_read_data(buf, fds[0], end, maxlen);

out:
	close(fds[0]);
	return ret;
}

static struct sj_backend shell_backend = {
	.get = shell_param_get,
};

static void sj_sigchld(int signo)
{
	do {} while (waitpid(-1, NULL, WNOHANG) > 0);
}

static void __constructor sj_shell_init(void)
{
	struct sigaction s = {};

	s.sa_handler = sj_sigchld;
	sigaction(SIGCHLD, &s, NULL);

	s.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &s, NULL);

	sj_backend_add(&shell_backend, "shell");
}
