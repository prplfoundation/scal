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

static struct blob_buf b, result;

static void
sj_param_prepare_script(struct sj_model *model, struct sj_object_param *par)
{
	struct sj_object *obj = par->obj;
	struct blob_attr *cur;
	int rem;

	if (obj) {
		if (par == obj->get_instance_keys)
			obj = obj->parent;

		sj_object_run_script(model, obj);
	}

	kvlist_free(&model->script_vars);
	kvlist_set(&model->script_vars, "parameter", sj_object_param_name(par));

	blobmsg_for_each_attr(cur, model->script_data, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		if (!blobmsg_check_attr(cur, true))
			continue;

		kvlist_set(&model->script_vars, blobmsg_name(cur),
			   blobmsg_get_string(cur));
	}
}

static int
sj_param_prepare(struct sj_model *model, struct sj_object_param *par,
		 struct blob_buf *buf)
{
	void *c;

	if (!par->script)
		sj_param_prepare_script(model, par);

	blob_buf_init(&b, 0);
	c = blobmsg_open_table(buf, "data");
	sj_script_eval_list(model, buf, par->backend_data);
	blobmsg_close_table(buf, c);

	return 0;
}

int
sj_param_get(struct sj_model *model, struct sj_object_param *par,
	     struct blob_attr **data)
{
	struct sj_backend *be = par->backend;
	int ret;

	if (!be)
		return SC_ERR_NOT_SUPPORTED;

	if (!be->default_session && be->session_alloc) {
		be->default_session = be->session_alloc(be);
		if (!be->default_session)
			return SC_ERR_UNKNOWN;
	}

	ret = sj_param_prepare(model, par, &b);
	if (ret)
		return ret;

	blob_buf_init(&result, 0);
	ret = be->get(be->default_session, blobmsg_data(b.head), &result);
	if (!blob_len(result.head))
	    return SC_ERR_NO_DATA;

	*data = blob_data(result.head);
	return ret;
}

void
sj_param_get_backend_info(struct sj_model *model, struct sj_object_param *par,
			  struct blob_buf *buf)
{
	struct sj_backend *be = par->backend;
	struct blob_attr *data;

	if (!be)
		return;

	if (sj_param_prepare(model, par, &b))
		return;

	data = blobmsg_data(b.head);
	blobmsg_add_string(buf, "backend", be->avl.key);
	blobmsg_add_field(buf, blobmsg_type(data), "backend_data",
			  blobmsg_data(data), blobmsg_data_len(data));
}
