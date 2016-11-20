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
#include "scald.h"

static struct blob_buf b;
static struct ubus_request_data *ubus_req;
static const char *ubus_method;

static struct ubus_method acl_object_methods[] = {};

static struct ubus_object_type acl_object_type =
	UBUS_OBJECT_TYPE("scald", acl_object_methods);

static struct ubus_object acl_object = {
	.name = "scald.acl",
	.type = &acl_object_type,
	.methods = acl_object_methods,
	.n_methods = ARRAY_SIZE(acl_object_methods),
};

void
scald_acl_req_init(struct ubus_request_data *req, const char *method)
{
	ubus_req = req;
	ubus_method = method;
}

void
scald_acl_req_done(void)
{
	ubus_req = NULL;
	ubus_method = NULL;
}

void
scald_acl_req_prepare(struct scapi_ptr *ptr)
{
	void *c;

	if (!acl_object.has_subscribers)
		return;

	blob_buf_init(&b, 0);

	blobmsg_add_string(&b, "method", ubus_method);
	c = blobmsg_open_array(&b, "path");
	if (ptr->path)
		blob_put_raw(&b, blobmsg_data(ptr->path), blobmsg_data_len(ptr->path));
	if (!strcmp(ubus_method, "list"))
		blobmsg_add_string(&b, NULL, ptr->obj->name);
	blobmsg_close_array(&b, c);

	if (ptr->plugin->object_get_acl)
		ptr->plugin->object_get_acl(ptr, &b);
}

void
scald_acl_req_add_param(struct scapi_ptr *ptr)
{
	if (!acl_object.has_subscribers)
		return;

	blobmsg_add_string(&b, "param", ptr->par->name);

	if (ptr->plugin->param_get_acl)
		ptr->plugin->param_get_acl(ptr, &b);
}

struct ubus_event_req {
	struct ubus_notify_request req;
	bool deny;
};

static void
acl_event_cb(struct ubus_notify_request *req, int idx, int ret)
{
	struct ubus_event_req *ureq = container_of(req, struct ubus_event_req, req);

	if (ret)
		ureq->deny = true;
}

int
scald_acl_req_check(struct scapi_ptr *ptr)
{
	struct ubus_event_req ureq = {};

	if (!acl_object.has_subscribers)
		return 0;

	if (ubus_notify_async(ubus_ctx, &acl_object, "check", b.head, &ureq.req))
		return 0;

	ureq.req.status_cb = acl_event_cb;
	ubus_complete_request(ubus_ctx, &ureq.req.req, 1000);

	if (ureq.deny)
		return SC_ERR_ACCESS_DENIED;

	return 0;
}

void scald_acl_init(struct ubus_context *ctx)
{
	ubus_add_object(ctx, &acl_object);
}
