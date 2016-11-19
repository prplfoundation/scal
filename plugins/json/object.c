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
#include "scapi_json.h"

static struct blob_buf b;

void
sj_object_run_script(struct sj_model *model, struct sj_object *obj)
{
	if (!obj)
		return;

	if (obj->parent)
		sj_object_run_script(model, obj->parent);

	if (!obj->data_script)
		return;

	blob_buf_init(&b, 0);
	model->script_obj = obj;
	json_script_run_file(&model->script, obj->data_script, b.head);
}

static struct sj_instance_list *
sj_object_get_instance_list(struct sj_object *obj, const char **path, int path_len)
{
	struct sj_instance_list *list;

	list_for_each_entry(list, &obj->instances, list) {
		if (!memcmp(list->path, path, path_len))
			return list;
	}

	return NULL;
}

int sj_object_get_instances(struct sj_model *model, struct sj_object *obj,
			    struct blob_attr **val)
{
	struct sj_instance_list *list;
	struct blob_attr *data, *cur;
	int rem, ret;
	const char **path;
	int i, path_len = 0;
	struct sj_object *obj_cur;

	if (!obj->get_instance_keys)
		return SC_ERR_INVALID_ARGUMENT;

	for (obj_cur = obj; obj_cur; obj_cur = obj_cur->parent)
		path_len += sizeof(*path);

	path = alloca(path_len);
	for (i = 0, obj_cur = obj->parent; obj_cur; obj_cur = obj_cur->parent)
		path[i++] = obj_cur->instance;
	path[i] = NULL;

	list = sj_object_get_instance_list(obj, path, path_len);
	if (list) {
		*val = list->data;
		return 0;
	}

	ret = sj_param_get(model, obj->get_instance_keys, &data);
	if (ret)
		return ret;

	blobmsg_for_each_attr(cur, data, rem) {
		if (!blobmsg_check_attr(cur, false) ||
		    blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			return SC_ERR_INVALID_DATA;
	}

	list = calloc_a(sizeof(*list) + path_len, &cur, blob_pad_len(data));
	memcpy(list->path, path, path_len);
	list->data = memcpy(cur, data, blob_pad_len(data));
	list_add(&list->list, &obj->instances);
	*val = list->data;

	return 0;
}

int sj_object_set_instance(struct sj_model *model, struct sj_object *obj, const char *name)
{
	struct blob_attr *cur, *list;
	int rem, ret;

	ret = sj_object_get_instances(model, obj, &list);
	if (ret)
		return ret;

	blobmsg_for_each_attr(cur, list, rem) {
		const char *cur_name = blobmsg_data(cur);

		if (strcmp(name, cur_name) != 0)
			continue;

		obj->instance = cur_name;
		return 0;
	}

	return SC_ERR_INVALID_ARGUMENT;
}
