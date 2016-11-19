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
#include <libubox/avl-cmp.h>
#include <glob.h>
#include "scapi_json.h"

static const struct scapi_cb *cb;
AVL_TREE(backends, avl_strcmp, false, NULL);
AVL_TREE(filters, avl_strcmp, false, NULL);

static int
sj_api_object_get(struct scapi_ptr *ptr)
{
	return -1;
}

static int
sj_api_object_list(struct scapi_ptr *ptr, scapi_object_cb fill,
		   struct scapi_list_ctx *ctx)
{
	return -1;
}

static int
sj_api_param_list(struct scapi_ptr *ptr, scapi_param_cb fill,
		  struct scapi_list_ctx *ctx)
{
	return -1;
}

static int
sj_api_param_get(struct scapi_ptr *ptr, const char *name)
{
	return -1;
}

static int
sj_api_param_read(struct scapi_ptr *ptr, struct blob_buf *buf)
{
	return -1;
}

static int
sj_api_param_write(struct scapi_ptr *ptr, struct blob_attr *val)
{
	return -1;
}

static void
sj_load_file(struct scapi_plugin *p, struct sj_model *sj, const char *file)
{
	cb->log_msg(p, SCAPI_LOG_DEBUG, "Load JSON file %s\n", file);
	sj_model_load_json(sj, file);
}

static void
sj_init_model(struct scapi_plugin *p, const char *name, glob_t *gl)
{
	struct scapi_model *model;
	struct sj_model *sj;
	int i;

	sj = calloc(1, sizeof(*sj));
	if (!sj)
		return;

	model = cb->model_add(p, name, sj);
	if (!model) {
		free(sj);
		return;
	}

	sj_model_init(sj);
	for (i = 0; i < gl->gl_pathc; i++)
		sj_load_file(p, sj, gl->gl_pathv[i]);
}

static void
sj_init_models(struct scapi_plugin *p)
{
	const char *dir = cb->option_get("json_dir");
	const char *models = cb->option_get("json_models");
	char *next, *buf, *name;
	int dir_len;

	if (!dir) {
		cb->log_msg(p, SCAPI_LOG_ERROR,
			    "No json dir specified, use -x json_dir=<path>\n");
		return;
	}

	if (!models) {
		cb->log_msg(p, SCAPI_LOG_ERROR,
			    "No JSON data models specified, use -x json_models=a,b,...\n");
		return;
	}

	dir_len = strlen(dir);

	buf = alloca(dir_len + strlen(models) + sizeof("/*.json"));

	memcpy(buf, dir, dir_len);
	buf[dir_len++] = '/';
	name = buf + dir_len;

	for (; models && *models; models = next) {
		glob_t gl;
		int len;

		next = strchr(models, ',');
		if (next)
			len = next++ - models;
		else
			len = strlen(models);

		memcpy(name, models, len);
		strcpy(name + len, "/*.json");

		glob(buf, 0, NULL, &gl);
		name[len] = 0;
		if (!gl.gl_pathc) {
			cb->log_msg(p, SCAPI_LOG_ERROR,
				    "No JSON data files for model %s\n", name);
			continue;
		}

		sj_init_model(p, name, &gl);
	}
}

void scapi_module_init(const struct scapi_cb *_cb)
{
	static struct scapi_plugin plugin = {
		.name = "json",

		.object_list = sj_api_object_list,
		.object_get = sj_api_object_get,

		.param_list = sj_api_param_list,
		.param_get = sj_api_param_get,
		.param_read = sj_api_param_read,
		.param_write = sj_api_param_write,
	};

	cb = _cb;
	cb->plugin_add(&plugin);
	sj_init_models(&plugin);
	sj_parser_free_data();
}
