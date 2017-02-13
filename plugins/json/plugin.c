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

const struct scapi_cb *cb;
AVL_TREE(backends, avl_strcmp, false, NULL);
AVL_TREE(filters, avl_strcmp, false, NULL);

static int
sj_api_object_get(struct scapi_ptr *ptr)
{
	struct sj_model *model = ptr->model_priv;
	struct sj_object *obj = NULL;
	bool instances;
	int ret;

	ret = sj_object_get_from_path(model, ptr->path, &obj, &instances);
	if (ret)
	    return ret;

	if (!obj)
		return SC_ERR_NOT_FOUND;

	ptr->obj = &obj->scapi;
	obj->scapi.name = instances ? sj_object_name(obj) : obj->instance;
	obj->scapi.multi_instance = instances;

	return 0;
}

static int
sj_api_object_list(struct scapi_ptr *ptr, scapi_object_cb fill,
		   struct scapi_list_ctx *ctx)
{
	struct sj_model *model = ptr->model_priv;
	struct sj_object *obj;
	bool instances;
	int ret;

	ret = sj_object_get_from_path(model, ptr->path, &obj, &instances);
	if (ret)
	    return ret;

	if (instances) {
		struct blob_attr *list, *cur;
		int rem;

		ret = sj_object_get_instances(model, obj, &list);
		if (ret)
			return ret;

		list = blob_memdup(list);
		if (!list)
			return SC_ERR_UNKNOWN;

		obj->scapi.multi_instance = false;
		blobmsg_for_each_attr(cur, list, rem) {
			const char *name = blobmsg_get_string(cur);

			if (sj_object_set_instance(model, obj, name))
				continue;

			obj->scapi.name = obj->instance;
			fill(ctx, &obj->scapi);
		}
		free(list);
	} else {
		struct avl_tree *list;
		struct sj_object *cur;

		list = obj ? &obj->objects : &model->objects;
		avl_for_each_element(list, cur, avl) {
			cur->scapi.name = sj_object_name(cur);
			cur->scapi.multi_instance = !!cur->get_instance_keys;
			fill(ctx, &cur->scapi);
		}
	}

	return 0;
}

static int
sj_api_object_add(struct scapi_ptr *ptr, const char *name, struct kvlist *values)
{
	struct sj_model *model = ptr->model_priv;
	struct sj_object *obj;
	bool instances;
	int ret;

	ret = sj_object_get_from_path(model, ptr->path, &obj, &instances);
	if (ret)
		return ret;

	if (!instances)
		return SC_ERR_NOT_SUPPORTED;

	return sj_object_add_instance(model, obj, name);
}

static int
sj_api_object_remove(struct scapi_ptr *ptr)
{
	struct sj_model *model = ptr->model_priv;
	struct sj_object *obj;
	bool instances;
	int ret;

	ret = sj_object_get_from_path(model, ptr->path, &obj, &instances);
	if (ret)
		return ret;

	if (instances || !obj->instance)
		return SC_ERR_NOT_SUPPORTED;

	return sj_object_remove_instance(model, obj, obj->instance);
}

static int
sj_api_param_list(struct scapi_ptr *ptr, scapi_param_cb fill,
		  struct scapi_list_ctx *ctx)
{
	struct sj_object *obj = container_of(ptr->obj, struct sj_object, scapi);
	struct sj_object_param *par;

	if (obj->scapi.multi_instance != !! obj->get_instance_keys)
		return 0;

	avl_for_each_element(&obj->params, par, avl)
		fill(ctx, &par->scapi);

	return 0;
}

static int
sj_api_param_get(struct scapi_ptr *ptr, const char *name)
{
	struct sj_object *obj = container_of(ptr->obj, struct sj_object, scapi);
	struct sj_object_param *par;

	par = avl_find_element(&obj->params, name, par, avl);
	if (!par)
		return SC_ERR_NOT_FOUND;

	ptr->par = &par->scapi;
	return 0;
}

static int
sj_api_param_read(struct scapi_ptr *ptr, struct blob_buf *buf)
{
	struct sj_model *model = ptr->model_priv;
	struct sj_object_param *par = container_of(ptr->par, struct sj_object_param, scapi);
	struct blob_attr *val;
	int ret;

	ret = sj_param_get(model, par, &val);
	if (ret)
		return ret;

	blobmsg_add_blob(buf, val);
	return 0;
}

static void
sj_api_param_get_acl(struct scapi_ptr *ptr, struct blob_buf *buf)
{
	struct sj_model *model = ptr->model_priv;
	struct sj_object_param *par = container_of(ptr->par, struct sj_object_param, scapi);

	sj_param_get_backend_info(model, par, buf);
}

static int
sj_api_param_write(struct scapi_ptr *ptr, struct blob_attr *val)
{
	struct sj_model *model = ptr->model_priv;
	struct sj_object_param *par = container_of(ptr->par, struct sj_object_param, scapi);

	return sj_param_set(model, par, val);
}

static int
sj_api_validate(struct scapi_ptr *ptr)
{
	struct sj_backend *be;

	avl_for_each_element(&backends, be, avl) {
		struct sj_session *s = be->default_session;
		int ret;

		if (!be->validate)
			continue;

		if (!s)
			continue;

		if (!s->changed)
			continue;

		ret = be->validate(s);
		if (ret)
			return ret;
	}

	return 0;
}

static int
sj_api_commit(struct scapi_ptr *ptr)
{
	struct sj_backend *be;
	int ret = 0;

	avl_for_each_element(&backends, be, avl) {
		struct sj_session *s = be->default_session;
		int r;

		if (!be->commit)
			continue;

		if (!s)
			continue;

		if (!s->changed)
			continue;

		s->changed = false;
		r = be->commit(s);
		if (r)
			ret = r;
	}

	return ret;
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

struct scapi_plugin plugin = {
	.name = "json",

	.object_list = sj_api_object_list,
	.object_get = sj_api_object_get,
	.object_add = sj_api_object_add,
	.object_remove = sj_api_object_remove,

	.param_list = sj_api_param_list,
	.param_get = sj_api_param_get,
	.param_read = sj_api_param_read,
	.param_write = sj_api_param_write,
	.param_get_acl = sj_api_param_get_acl,

	.validate = sj_api_validate,
	.commit = sj_api_commit,
};

void __attribute__ ((visibility ("default")))
scapi_module_init(const struct scapi_cb *_cb)
{
	cb = _cb;
	cb->plugin_add(&plugin);
	sj_init_models(&plugin);
	sj_parser_free_data();
}
