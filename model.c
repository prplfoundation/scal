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
#include <libubox/kvlist.h>
#include "scapi.h"
#include "scald.h"

struct scald_object_entry {
	unsigned long plugins;
};

struct scald_param_entry {
	bool readonly;
	int ofs_value;

	char data[];
};

struct scapi_list_ctx {
	struct scald_object_entry obj_buf;
	struct scald_param_entry *par_buf;
	int buf_len;

	struct kvlist kv;
	int plugin;
	bool values;
};

static struct blob_buf b;

static int kvlist_scald_object_entry_len(struct kvlist *kv, const void *data)
{
	return sizeof(struct scald_object_entry);
}

static int kvlist_scald_param_entry_len(struct kvlist *kv, const void *data)
{
	const struct scald_param_entry *e = data;
	int ov = e->ofs_value;

	return ov + strlen(e->data + ov) + 1;
}

typedef int (*scald_len_cb)(struct kvlist *kv, const void *data);

#define ptr_model(_ptr) \
	container_of((_ptr)->model, struct scald_model, scapi)

#define scald_model_iterate_plugins(_ctx, _ptr) \
	for ((_ctx)->plugin = 0, \
	       (_ptr)->plugin = ptr_model(_ptr)->plugins[0],		       \
	       (_ptr)->model_priv = ptr_model(_ptr)->plugin_priv[0];	       \
	     (_ctx)->plugin < ptr_model(_ptr)->n_plugins;		       \
	     (_ptr)->plugin = ptr_model(_ptr)->plugins[++(_ctx)->plugin],      \
	       (_ptr)->model_priv = ptr_model(_ptr)->plugin_priv[(_ctx)->plugin])

static void scald_model_iterate_init(struct scapi_list_ctx *ctx, scald_len_cb cb)
{
	memset(ctx, 0, sizeof(*ctx));
	kvlist_init(&ctx->kv, cb);
}

static void scald_model_iterate_done(struct scapi_list_ctx *ctx)
{
	kvlist_free(&ctx->kv);
	free(ctx->par_buf);
}

enum {
	M_OBJ_PATH,
	M_OBJ_NAME,
	M_OBJ_VALUE,
	__M_OBJ_MAX
};

static const struct blobmsg_policy obj_policy[__M_OBJ_MAX] = {
	[M_OBJ_PATH] = { "path", BLOBMSG_TYPE_ARRAY },
	[M_OBJ_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[M_OBJ_VALUE] = { "value", BLOBMSG_TYPE_STRING },
};

#define M_OBJ_MASK (1 << M_OBJ_PATH)
#define M_GET_MASK (M_OBJ_MASK | (1 << M_OBJ_NAME))
#define M_SET_MASK (M_GET_MASK | (1 << M_OBJ_VALUE))

static void
scald_model_handle_list_cb(struct scapi_list_ctx *ctx, struct scapi_object *obj)
{
	struct scald_object_entry *cur;

	cur = kvlist_get(&ctx->kv, obj->name);
	if (!cur) {
		kvlist_set(&ctx->kv, obj->name, &ctx->obj_buf);
		return;
	}

	cur->plugins |= ctx->obj_buf.plugins;
}

static int
scald_model_handle_list(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct scald_model *m = container_of(obj, struct scald_model, ubus);
	struct scapi_ptr ptr = { .model = &m->scapi };
	struct blob_attr *tb[__M_OBJ_MAX];
	struct scapi_list_ctx lctx;
	struct scald_object_entry *e;
	const char *name;
	void *c;

	blobmsg_parse(obj_policy, __M_OBJ_MAX, tb, blob_data(msg), blob_len(msg));
	ptr.path = tb[M_OBJ_PATH];

	scald_model_iterate_init(&lctx, kvlist_scald_object_entry_len);
	scald_model_iterate_plugins(&lctx, &ptr) {
		lctx.obj_buf.plugins = 1 << lctx.plugin;
		ptr.plugin->object_list(&ptr, scald_model_handle_list_cb, &lctx);
	}

	blob_buf_init(&b, 0);
	c = blobmsg_open_array(&b, "objects");
	kvlist_for_each(&lctx.kv, name, e) {
		blobmsg_add_string(&b, NULL, name);
	}
	blobmsg_close_array(&b, c);
	scald_model_iterate_done(&lctx);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static void
scald_model_handle_param_cb(struct scapi_list_ctx *ctx, struct scapi_parameter *par)
{
	struct scald_param_entry *cur;
	int val_len = 1;
	int len;
	char *data;

	cur = kvlist_get(&ctx->kv, par->name);
	if (cur)
		return;

	len = sizeof(*cur) + val_len;
	if (len > ctx->buf_len) {
		void *new_buf;

		new_buf = realloc(ctx->par_buf, len + 32);
		if (!new_buf)
			return;

		ctx->par_buf = new_buf;
		ctx->buf_len = len + 32;
	}

	cur = ctx->par_buf;
	data = cur->data;
	memset(cur, 0, sizeof(*cur));
	cur->readonly = par->readonly;

	*data = 0;
	cur->ofs_value = data - cur->data;

	kvlist_set(&ctx->kv, par->name, cur);
}

static int
scald_model_handle_info(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct scald_model *m = container_of(obj, struct scald_model, ubus);
	struct scapi_ptr ptr = { .model = &m->scapi };
	struct blob_attr *tb[__M_OBJ_MAX];
	struct scapi_list_ctx lctx;
	struct scald_param_entry *e;
	const char *name;
	void *c;

	blobmsg_parse(obj_policy, __M_OBJ_MAX, tb, blob_data(msg), blob_len(msg));

	ptr.path = tb[M_OBJ_PATH];
	if (!ptr.path)
	    return UBUS_STATUS_INVALID_ARGUMENT;

	scald_model_iterate_init(&lctx, kvlist_scald_param_entry_len);
	scald_model_iterate_plugins(&lctx, &ptr) {
		if (ptr.plugin->object_get(&ptr))
			continue;

		ptr.plugin->param_list(&ptr, scald_model_handle_param_cb, &lctx);
	}

	blob_buf_init(&b, 0);
	c = blobmsg_open_table(&b, "parameters");
	kvlist_for_each(&lctx.kv, name, e) {
		void *c2 = blobmsg_open_table(&b, name);
		blobmsg_add_u8(&b, "readonly", e->readonly);
		blobmsg_close_table(&b, c2);
	}
	blobmsg_close_table(&b, c);
	scald_model_iterate_done(&lctx);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int
scald_model_handle_get(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	struct scald_model *m = container_of(obj, struct scald_model, ubus);
	struct scapi_ptr ptr = { .model = &m->scapi };
	struct blob_attr *tb[__M_OBJ_MAX];
	struct scapi_list_ctx lctx;
	int ret = UBUS_STATUS_NOT_FOUND;
	const char *name;

	blobmsg_parse(obj_policy, __M_OBJ_MAX, tb, blob_data(msg), blob_len(msg));

	ptr.path = tb[M_OBJ_PATH];
	if (!ptr.path || !tb[M_OBJ_NAME])
	    return UBUS_STATUS_INVALID_ARGUMENT;

	name = blobmsg_get_string(tb[M_OBJ_NAME]);

	blob_buf_init(&b, 0);
	scald_model_iterate_plugins(&lctx, &ptr) {
		if (ptr.plugin->object_get(&ptr))
			continue;

		if (ptr.plugin->param_get(&ptr, name))
			continue;

		if (ptr.plugin->param_read(&ptr, &b) == 0)
			ret = 0;

		ubus_send_reply(ctx, req, b.head);
		break;
	}

	return ret;
}

static int
scald_model_handle_set(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	struct scald_model *m = container_of(obj, struct scald_model, ubus);
	struct scapi_ptr ptr = { .model = &m->scapi };
	struct blob_attr *tb[__M_OBJ_MAX];
	struct scapi_list_ctx lctx;
	const char *name;

	blobmsg_parse(obj_policy, __M_OBJ_MAX, tb, blob_data(msg), blob_len(msg));

	ptr.path = tb[M_OBJ_PATH];
	if (!ptr.path || !tb[M_OBJ_NAME] || !tb[M_OBJ_VALUE])
	    return UBUS_STATUS_INVALID_ARGUMENT;

	name = blobmsg_get_string(tb[M_OBJ_NAME]);

	blob_buf_init(&b, 0);
	scald_model_iterate_plugins(&lctx, &ptr) {
		if (ptr.plugin->object_get(&ptr))
			continue;

		if (ptr.plugin->param_get(&ptr, name))
			continue;

		if (ptr.par->readonly)
			return UBUS_STATUS_PERMISSION_DENIED;

		if (ptr.plugin->param_write(&ptr, tb[M_OBJ_VALUE]) != 0)
			return UBUS_STATUS_UNKNOWN_ERROR;

		return 0;
	}

	return UBUS_STATUS_NOT_FOUND;
}

static struct ubus_method model_object_methods[] = {
	UBUS_METHOD_MASK("list", scald_model_handle_list, obj_policy, M_OBJ_MASK),
	UBUS_METHOD_MASK("info", scald_model_handle_info, obj_policy, M_OBJ_MASK),
	UBUS_METHOD_MASK("get", scald_model_handle_get, obj_policy, M_GET_MASK),
	UBUS_METHOD_MASK("set", scald_model_handle_set, obj_policy, M_SET_MASK),
};

static struct ubus_object_type model_object_type =
	UBUS_OBJECT_TYPE("scald.model", model_object_methods);

struct scald_model *
scald_model_new(const char *name)
{
	struct scald_model *m;
	char *name_buf;

	m = calloc_a(sizeof(*m), &name_buf, 4 /* scald. */ + strlen(name) + 1);
	if (!m)
		return NULL;

	sprintf(name_buf, "scald.%s", name);
	m->scapi.name = m->avl.key = name_buf + 4;

	m->ubus.name = name_buf;
	m->ubus.type = &model_object_type;
	m->ubus.methods = model_object_methods;
	m->ubus.n_methods = ARRAY_SIZE(model_object_methods);

	if (ubus_add_object(ubus_ctx, &m->ubus)) {
		free(m);
		return NULL;
	}

	return m;
}
