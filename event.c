/*
 * Copyright (C) 2016-2017 prpl Foundation
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
#include "scald.h"

struct blob_buf *scald_event_new(struct ubus_object *obj)
{
	static struct blob_buf b;

	if (!obj->has_subscribers)
		return NULL;

	blob_buf_init(&b, 0);
	return &b;
}

void scald_event_add_ptr(struct blob_buf *buf, struct scapi_ptr *ptr,
			 enum scapi_ptr_type type)
{
	struct scald_model *m = container_of(ptr->model, struct scald_model, scapi);
	void *c;

	if (!buf)
		return;

	blobmsg_add_string(buf, "model", m->scapi.name);
	blobmsg_add_string(buf, "plugin", ptr->plugin->name);

	if (type == SCAPI_PTR_PLUGIN)
		return;

	c = blobmsg_open_array(buf, "path");
	if (ptr->path)
		blob_put_raw(buf, blobmsg_data(ptr->path), blobmsg_data_len(ptr->path));
	if (type == SCAPI_PTR_OBJ_ENTRY)
		blobmsg_add_string(buf, NULL, ptr->obj->name);
	blobmsg_close_array(buf, c);

	if (ptr->plugin->object_get_acl)
		ptr->plugin->object_get_acl(ptr, buf);

	if (type < SCAPI_PTR_PARAM)
		return;

	blobmsg_add_string(buf, "param", ptr->par->name);

	if (ptr->plugin->param_get_acl)
		ptr->plugin->param_get_acl(ptr, buf);
}
