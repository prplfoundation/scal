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
#include <string.h>
#include <stdio.h>
#include <glob.h>
#include <stdlib.h>
#include <dirent.h>

#include <libubox/blobmsg_json.h>
#include <libubox/kvlist.h>
#include <libubox/utils.h>
#include <libubox/avl-cmp.h>

#include "scapi_json.h"

static struct blob_buf obj_buf, b;

static struct sj_object *sj_object_get(struct avl_tree *tree, const char *name)
{
	struct sj_object *obj;
	char *name_buf;

	obj = avl_find_element(tree, name, obj, avl);
	if (obj)
		return obj;

	obj = calloc_a(sizeof(*obj), &name_buf, strlen(name) + 1);
	obj->avl.key = strcpy(name_buf, name);
	avl_init(&obj->objects, avl_strcmp, false, NULL);
	avl_init(&obj->params, avl_strcmp, false, NULL);
	avl_init(&obj->script_params, avl_strcmp, false, NULL);
	INIT_LIST_HEAD(&obj->instances);
	avl_insert(tree, &obj->avl);

	return obj;
}

static void
merge_backend_data(struct blob_buf *buf, struct blob_attr *base, struct blob_attr *param)
{
	static struct kvlist kv;
	struct blob_attr *cur;
	const char *name;
	int rem;

	kvlist_init(&kv, kvlist_blob_len);

	blobmsg_for_each_attr(cur, base, rem)
		kvlist_set(&kv, blobmsg_name(cur), cur);
	blobmsg_for_each_attr(cur, param, rem)
		kvlist_set(&kv, blobmsg_name(cur), cur);

	kvlist_for_each(&kv, name, cur)
		blobmsg_add_blob(buf, cur);

	kvlist_free(&kv);
}

static struct sj_object_param *
sj_param_create(struct sj_model *ctx, const char *name, const char *type,
		 const char *backend_name, const struct blob_attr *backend_data,
		 const char *filter_name, const struct blob_attr *filter_data)
{
	const struct sj_filter *filter;
	struct sj_object_param *par;
	char *type_buf, *name_buf;
	struct blob_attr *bdata;
	struct blob_attr *fdata;

	filter = sj_filter_get(filter_name);
	par = calloc_a(sizeof(*par),
		&type_buf, strlen(type) + 1,
		&name_buf, strlen(name) + 1,
		&bdata, blob_pad_len(backend_data),
		&fdata, (filter && filter_data) ? blob_pad_len(filter_data) : 0);

	par->avl.key = strcpy(name_buf, name);
	par->backend = sj_backend_get(backend_name);
	par->type = strcpy(type_buf, type);
	par->backend_data = memcpy(bdata, backend_data, blob_pad_len(backend_data));
	par->filter = sj_filter_get(filter_name);
	if (par->filter && filter_data)
		par->filter_data = memcpy(fdata, filter_data, blob_pad_len(filter_data));

	return par;
}

static struct sj_object_param *
sj_object_param_create(struct sj_model *ctx, struct sj_object *obj, struct blob_attr *data,
		     const char *backend_name, struct blob_attr *backend_data,
		     const char *type)
{
	enum {
		PARAM_TYPE,
		PARAM_READONLY,
		PARAM_HIDDEN,
		PARAM_BACKEND,
		PARAM_BACKEND_DATA,
		PARAM_FILTER,
		PARAM_FILTER_DATA,
		__PARAM_MAX
	};
	static const struct blobmsg_policy policy[__PARAM_MAX] = {
		[PARAM_TYPE] = { "type", BLOBMSG_TYPE_STRING },
		[PARAM_READONLY] = { "readonly", BLOBMSG_TYPE_BOOL },
		[PARAM_HIDDEN] = { "hidden", BLOBMSG_TYPE_BOOL },
		[PARAM_BACKEND] = { "backend", BLOBMSG_TYPE_STRING },
		[PARAM_BACKEND_DATA] = { "backend_data", BLOBMSG_TYPE_TABLE },
		[PARAM_FILTER] = { "filter", BLOBMSG_TYPE_STRING },
		[PARAM_FILTER_DATA] = { "filter_data", BLOBMSG_TYPE_TABLE },
	};
	struct sj_object_param *par;
	struct blob_attr *tb[__PARAM_MAX];
	const char *name = blobmsg_name(data);
	const char *filter_name = NULL;

	blobmsg_parse(policy, ARRAY_SIZE(policy), tb, blobmsg_data(data), blobmsg_data_len(data));

	blob_buf_init(&b, 0);

	if (tb[PARAM_TYPE])
		type = blobmsg_data(tb[PARAM_TYPE]);

	if (tb[PARAM_BACKEND]) {
		backend_data = tb[PARAM_BACKEND_DATA];
		backend_name = blobmsg_data(tb[PARAM_BACKEND]);
	} else if (backend_data) {
		if (tb[PARAM_BACKEND_DATA]) {
			merge_backend_data(&b, backend_data, tb[PARAM_BACKEND_DATA]);
			backend_data = b.head;
		}
	} else {
		backend_data = tb[PARAM_BACKEND_DATA];
	}

	if (tb[PARAM_FILTER])
	    filter_name = blobmsg_get_string(tb[PARAM_FILTER]);

	if (!backend_name)
		return NULL;

	if (!backend_data)
		backend_data = b.head;

	par = sj_param_create(ctx, name, type,
			       backend_name, backend_data,
			       filter_name, tb[PARAM_FILTER_DATA]);
	par->obj = obj;

	if (tb[PARAM_READONLY])
		par->readonly = blobmsg_get_bool(tb[PARAM_READONLY]);

	if (tb[PARAM_HIDDEN])
		par->hidden = blobmsg_get_bool(tb[PARAM_HIDDEN]);

	return par;
}

static int
sj_object_param_add(struct sj_model *ctx, struct sj_object *obj,
		     struct avl_tree *tree, struct blob_attr *data,
		     const char *backend_name, struct blob_attr *backend_data,
		     const char *type)
{
	const char *name = blobmsg_name(data);
	struct sj_object_param *par;

	if (!name[0])
		return 0;

	if (avl_find(tree, name))
		return 0;

	par = sj_object_param_create(ctx, obj, data, backend_name, backend_data, type);
	if (!par)
		return 0;

	if (avl_insert(tree, &par->avl)) {
		free(par);
		return 0;
	}

	return 1;
}

static void
sj_object_add_instance_data(struct sj_model *ctx, struct sj_object *obj,
			     struct blob_attr *attr, const char *backend,
			     struct blob_attr *backend_data)
{
	struct sj_object_param *par;

	if (!attr)
		return;

	par = sj_object_param_create(ctx, obj, attr, backend, backend_data, "");
	if (!par)
		return;

	free(obj->get_instance_keys);
	obj->get_instance_keys = par;
}

static void
sj_object_add_script(struct sj_object *obj, struct blob_attr *attr)
{
	if (!attr)
		return;

	free(obj->data_script);
	obj->data_script = json_script_file_from_blobmsg("", attr, blob_pad_len(attr));
}

static int
sj_object_add_params(struct sj_model *ctx, struct sj_object *obj,
		      struct avl_tree *tree, struct blob_attr *data,
		      const char *backend, struct blob_attr *backend_data,
		      const char *default_type)
{
	struct blob_attr *cur;
	int rem;
	int n = 0;

	if (!data)
		return 0;

	blobmsg_for_each_attr(cur, data, rem)
		n += sj_object_param_add(ctx, obj, tree, cur,
					  backend, backend_data,
					  default_type);

	return n;
}

static void
sj_object_add(struct sj_model *ctx, struct sj_object *obj, struct blob_attr *attr)
{
	enum {
		OBJ_BACKEND,
		OBJ_BACKEND_DATA,
		OBJ_PARAM,
		OBJ_GET_KEYS,
		OBJ_DATA_SCRIPT,
		OBJ_DEFAULT_TYPE,
		OBJ_SCRIPT_PARAMS,
		__OBJ_MAX
	};
	static const struct blobmsg_policy policy[__OBJ_MAX] = {
		[OBJ_BACKEND] = { "backend", BLOBMSG_TYPE_STRING },
		[OBJ_BACKEND_DATA] = { "backend_data", BLOBMSG_TYPE_TABLE },
		[OBJ_PARAM] = { "parameters", BLOBMSG_TYPE_TABLE },
		[OBJ_GET_KEYS] = { "get_instance_keys", BLOBMSG_TYPE_TABLE },
		[OBJ_DATA_SCRIPT] = { "data_script", BLOBMSG_TYPE_ARRAY },
		[OBJ_DEFAULT_TYPE] = { "default_type", BLOBMSG_TYPE_STRING },
		[OBJ_SCRIPT_PARAMS] = { "script_parameters", BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *tb[__OBJ_MAX];
	struct blob_attr *backend_data = NULL;
	const char *backend = NULL;
	const char *default_type = "";
	int n;

	blobmsg_parse(policy, ARRAY_SIZE(policy), tb, blobmsg_data(attr), blobmsg_data_len(attr));
	sj_object_add_script(obj, tb[OBJ_DATA_SCRIPT]);

	if (tb[OBJ_BACKEND]) {
		backend = blobmsg_data(tb[OBJ_BACKEND]);
		backend_data = tb[OBJ_BACKEND_DATA];
	}

	sj_object_add_instance_data(ctx, obj, tb[OBJ_GET_KEYS], backend, backend_data);

	if (tb[OBJ_DEFAULT_TYPE])
	    default_type = blobmsg_get_string(tb[OBJ_DEFAULT_TYPE]);

	n = sj_object_add_params(ctx, obj, &obj->params, tb[OBJ_PARAM],
				  backend, backend_data, default_type);
	obj->n_params += n;

	sj_object_add_params(ctx, obj, &obj->script_params, tb[OBJ_SCRIPT_PARAMS],
			      backend, backend_data, default_type);
}

static void
sj_object_attr_add(struct sj_model *ctx, struct blob_attr *attr)
{
	struct blobmsg_policy pol[2] = {
		{ .type = BLOBMSG_TYPE_UNSPEC },
		{ .type = BLOBMSG_TYPE_TABLE },
	};
	struct sj_object *obj = NULL;
	struct avl_tree *tree = &ctx->objects;
	struct blob_attr *tb[2], *cur;
	int rem;

	BUILD_BUG_ON(ARRAY_SIZE(pol) != ARRAY_SIZE(tb));

	blobmsg_parse_array(pol, ARRAY_SIZE(pol), tb, blobmsg_data(attr), blobmsg_data_len(attr));
	if (!tb[0] || !tb[1])
		return;

	switch (blobmsg_type(tb[0])) {
	case BLOBMSG_TYPE_STRING:
		obj = sj_object_get(&ctx->objects, blobmsg_data(tb[0]));
		sj_object_add(ctx, obj, tb[1]);
		break;
	case BLOBMSG_TYPE_ARRAY:
		blobmsg_for_each_attr(cur, tb[0], rem) {
			struct sj_object *parent = obj;

			if (!blobmsg_check_attr(cur, false))
				return;

			obj = sj_object_get(tree, blobmsg_data(cur));
			obj->parent = parent;
			tree = &obj->objects;
		}

		if (!obj)
			return;

		sj_object_add(ctx, obj, tb[1]);;
		break;
	default:
		break;
	}
}

void sj_model_init(struct sj_model *m)
{
	avl_init(&m->objects, avl_strcmp, false, NULL);
	avl_init(&m->filters, avl_strcmp, false, NULL);
}

int sj_model_load_json(struct sj_model *ctx, const char *path)
{
	static const struct blobmsg_policy obj_p = {
		"objects", BLOBMSG_TYPE_ARRAY
	};
	struct blob_attr *obj_list, *cur;
	int rem;

	blob_buf_init(&obj_buf, 0);
	blobmsg_add_json_from_file(&obj_buf, path);

	blobmsg_parse(&obj_p, 1, &obj_list, blob_data(obj_buf.head), blob_len(obj_buf.head));
	if (!obj_list)
		return -1;

	blobmsg_for_each_attr(cur, obj_list, rem)
		sj_object_attr_add(ctx, cur);

	return 0;
}

void sj_parser_free_data(void)
{
	blob_buf_free(&b);
	blob_buf_free(&obj_buf);
}
