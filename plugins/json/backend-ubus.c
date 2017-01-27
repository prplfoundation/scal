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
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include "scapi_json.h"

struct ubus_session {
	struct sj_session scapi;
	struct ubus_context ctx;
};

struct ubus_param_data {
	struct blob_buf *buf;
	struct blob_attr *key;
	const char *select;
	int ret;
};

static inline struct ubus_session *
ubus_session(struct sj_session *s)
{
	return container_of(s, struct ubus_session, scapi);
}

static void
ubus_param_get_json(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct ubus_param_data *pdata = req->priv;

	pdata->ret = sj_filter_json(pdata->buf, msg, pdata->key, pdata->select);
}

static int ubus_param_get(struct sj_session *as, struct blob_attr *data, struct blob_buf *buf)
{
	enum {
		DATA_OBJECT,
		DATA_METHOD,
		DATA_MESSAGE,
		DATA_TIMEOUT,
		DATA_KEY,
		DATA_SELECT,
		__DATA_MAX
	};
	static const struct blobmsg_policy policy[__DATA_MAX] = {
		[DATA_OBJECT] = { "object", BLOBMSG_TYPE_STRING },
		[DATA_METHOD] = { "method", BLOBMSG_TYPE_STRING },
		[DATA_MESSAGE] = { "message", BLOBMSG_TYPE_TABLE },
		[DATA_TIMEOUT] = { "timeout", BLOBMSG_TYPE_INT32 },
		[DATA_KEY] = { "key", BLOBMSG_TYPE_UNSPEC },
		[DATA_SELECT] = { "select", BLOBMSG_TYPE_STRING },
	};
	struct ubus_context *ctx = &ubus_session(as)->ctx;
	struct ubus_param_data pdata = {};
	static struct blob_buf b;
	struct blob_attr *tb[__DATA_MAX];
	int timeout = 10000;
	uint32_t id;

	blobmsg_parse(policy, __DATA_MAX, tb, blobmsg_data(data), blobmsg_data_len(data));

	if (!tb[DATA_OBJECT] || !tb[DATA_METHOD] || !tb[DATA_KEY])
		return SC_ERR_INVALID_ARGUMENT;

	pdata.buf = buf;
	pdata.key = tb[DATA_KEY];
	pdata.ret = SC_ERR_NOT_FOUND;

	if (tb[DATA_SELECT])
		pdata.select = blobmsg_data(tb[DATA_SELECT]);

	blob_buf_init(&b, 0);
	if (tb[DATA_MESSAGE])
		blob_put_raw(&b, blobmsg_data(tb[DATA_MESSAGE]), blobmsg_len(tb[DATA_MESSAGE]));

	if (tb[DATA_TIMEOUT])
		timeout = blobmsg_get_u32(tb[DATA_TIMEOUT]);

	if (ubus_lookup_id(ctx, blobmsg_data(tb[DATA_OBJECT]), &id))
		return SC_ERR_NOT_FOUND;

	ubus_invoke(ctx, id, blobmsg_data(tb[DATA_METHOD]),
		    b.head, ubus_param_get_json, &pdata, timeout);

	return pdata.ret;
}

static struct sj_session *ubus_backend_session_alloc(struct sj_backend *ctx)
{
	struct ubus_session *s;

	s = calloc(1, sizeof(*s));
	if (ubus_connect_ctx(&s->ctx, NULL)) {
		free(s);
		return NULL;
	}

	return &s->scapi;
}

static void ubus_backend_session_free(struct sj_backend *ctx, struct sj_session *as)
{
	struct ubus_session *s = ubus_session(as);
	ubus_shutdown(&s->ctx);
	free(s);
}


static struct sj_backend ubus_backend = {
	.session_alloc = ubus_backend_session_alloc,
	.session_free = ubus_backend_session_free,

	.get = ubus_param_get,
};

static void __constructor sj_ubus_init(void)
{
	sj_backend_add(&ubus_backend, "ubus");
}
