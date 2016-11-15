/*
 * Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
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
#include <libubox/uloop.h>
#include <sys/stat.h>
#include <getopt.h>
#include <glob.h>
#include "scald.h"

#ifndef SCALD_PLUGIN_PATH
#define SCALD_PLUGIN_PATH		"/usr/lib/scald"
#endif

static void load_plugins(const char *path)
{
	struct stat st;
	char *pattern;
	glob_t gl;
	int i;

	if (stat(path, &st) < 0)
		return;

	if ((st.st_mode & S_IFMT) == S_IFREG) {
		scald_plugin_load(path);
		return;
	}

	pattern = alloca(strlen(path) + 6);
	sprintf(pattern, "%s/*.so", path);
	glob(pattern, 0, NULL, &gl);
	for (i = 0; i < gl.gl_pathc; i++)
		scald_plugin_load(gl.gl_pathv[i]);

	globfree(&gl);
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Options:\n"
		"	-s <path>:		Path to the ubus socket\n"
		"	-p <path>:		Path to plugins (default: %s)\n"
		"	-x <name>[=<val>]:	Set an option used by a plugin\n"
		"\n", progname, SCALD_PLUGIN_PATH);
}

static int scald_init(int argc, char **argv)
{
	const char *plugin_path = SCALD_PLUGIN_PATH;
	const char *socket = NULL;
	int ch;

	uloop_init();

	while ((ch = getopt(argc, argv, "s:p:x:")) != -1) {
		switch (ch) {
		case 's':
			socket = optarg;
			break;
		case 'p':
			plugin_path = optarg;
			break;
		case 'x':
			scald_plugin_add_option(optarg);
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (scald_ubus_init(socket))
		return 1;

	load_plugins(plugin_path);
	return 0;
}

int main(int argc, char **argv)
{
	if (scald_init(argc, argv))
		return 1;

	uloop_run();
	uloop_done();

	return 0;
}
