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

static int static_param_get(struct sj_session *ctx, struct blob_attr *data, struct blob_buf *buf)
{
	static const struct blobmsg_policy policy = { "value", BLOBMSG_TYPE_UNSPEC };
	struct blob_attr *val;

	blobmsg_parse(&policy, 1, &val, blobmsg_data(data), blobmsg_data_len(data));
	if (!val)
		return SC_ERR_INVALID_DATA;

	blobmsg_add_blob(buf, val);
	return 0;
}

static struct sj_backend static_backend = {
	.get = static_param_get,
};

static void __constructor sj_static_init(void)
{
	sj_backend_add(&static_backend, "static");
}
