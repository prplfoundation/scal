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
#include "scapi.h"

static const struct scapi_cb *cb;
static const struct scapi_model *model;

struct x_param {
	struct scapi_parameter par;
	const char *value;
	char *new_value;
};

struct x_object {
	struct x_object *next;
	struct x_object *sub[4];
	struct scapi_object obj;

	struct x_param *params;
};

struct x_param mgmt_par[] = {
	{
		.par.name = "Username",
		.value = "foo",
	},
	{
		.par.name = "Password",
		.value = "bar",
	},
	{}
};

static struct x_object mgmt = {
	.obj.name = "ManagementServer",
	.params = mgmt_par,
};

static struct x_object device = {
	.obj.name = "Device",
	.sub = {
		&mgmt
	},
};

static struct x_object root = {
	.sub = {
		&device
	},
};

static struct x_object *
get_next(struct x_object *obj, const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(obj->sub); i++) {
		struct x_object *cur = obj->sub[i];

		if (!cur)
			break;

		if (!strcmp(name, cur->obj.name))
			return cur;
	}

	return NULL;
}

static struct x_object *
get_object(struct blob_attr *path)
{
	struct x_object *obj = &root;
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, path, rem) {
		obj = get_next(obj, blobmsg_get_string(cur));
		if (!obj)
			return NULL;
	}

	if (!obj)
		return NULL;

	return obj;
}


static int
plugin_object_get(struct scapi_ptr *ptr)
{
	struct x_object *o = get_object(ptr->path);

	if (!o || o == &root)
		return -1;

	ptr->obj = &o->obj;
	return 0;
}

static int
plugin_object_list(struct scapi_ptr *ptr, scapi_object_cb fill,
		   struct scapi_list_ctx *ctx)
{
	struct x_object *obj = get_object(ptr->path);
	int i;

	if (!obj)
		return 0;

	for (i = 0; i < ARRAY_SIZE(obj->sub); i++) {
		if (!obj->sub[i])
			break;

		fill(ctx, &obj->sub[i]->obj);
	}

	return 0;
}

static int
plugin_param_list(struct scapi_ptr *ptr, scapi_param_cb fill,
		  struct scapi_list_ctx *ctx)
{
	struct x_object *obj = container_of(ptr->obj, struct x_object, obj);
	struct x_param *par;

	for (par = obj->params; par && par->par.name; par++)
		fill(ctx, &par->par);

	return 0;
}

static int
plugin_param_get(struct scapi_ptr *ptr, const char *name)
{
	struct x_object *obj = container_of(ptr->obj, struct x_object, obj);
	struct x_param *par;

	for (par = obj->params; par && par->par.name; par++) {
		if (strcmp(par->par.name, name) != 0)
			continue;

		ptr->par = &par->par;
		return 0;
	}

	return -1;
}

static int
plugin_param_read(struct scapi_ptr *ptr, struct blob_buf *buf)
{
	struct x_param *par = container_of(ptr->par, struct x_param, par);
	const char *val = par->new_value ? par->new_value : par->value;

	blobmsg_add_string(buf, "value", val);
	return 0;
}

static int
plugin_param_write(struct scapi_ptr *ptr, struct blob_attr *val)
{
	struct x_param *par = container_of(ptr->par, struct x_param, par);

	free(par->new_value);
	par->new_value = strdup(blobmsg_get_string(val));

	return 0;
}

static struct scapi_plugin plugin = {
	.name = "example",

	.object_list = plugin_object_list,
	.object_get = plugin_object_get,

	.param_list = plugin_param_list,
	.param_get = plugin_param_get,
	.param_read = plugin_param_read,
	.param_write = plugin_param_write,
};

void scapi_module_init(const struct scapi_cb *_cb)
{
	cb = _cb;

	cb->plugin_add(&plugin);
	cb->log_msg(&plugin, SCAPI_LOG_INFO, "Demo module init!\n");
	model = cb->model_add(&plugin, "tr-181", NULL);
}
