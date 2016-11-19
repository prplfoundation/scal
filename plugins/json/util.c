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

static void
sj_add_backend_data(struct sj_model *model, struct blob_buf *buf,
		    struct blob_attr *cur)
{
	void *c;

	switch (blobmsg_type(cur)) {
	case BLOBMSG_TYPE_ARRAY:
		c = blobmsg_open_array(buf, blobmsg_name(cur));
		sj_script_eval_list(model, buf, cur);
		blobmsg_close_array(buf, c);
		break;
	case BLOBMSG_TYPE_TABLE:
		c = blobmsg_open_table(buf, blobmsg_name(cur));
		sj_script_eval_list(model, buf, cur);
		blobmsg_close_table(buf, c);
		break;
	case BLOBMSG_TYPE_STRING:
		json_script_eval_string(&model->script, NULL, buf,
					blobmsg_name(cur), blobmsg_data(cur));
		break;
	default:
		blobmsg_add_blob(buf, cur);
		break;
	}
}

void
sj_script_eval_list(struct sj_model *model, struct blob_buf *buf,
		      struct blob_attr *data)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, data, rem) {
		if (!blobmsg_check_attr(cur, false))
			continue;

		sj_add_backend_data(model, buf, cur);
	}
}


static struct blob_attr *
__sj_filter_json_table(struct blob_attr *data, const char *key)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, data, rem) {
		if (strcmp(key, blobmsg_name(cur)) != 0)
			continue;

		return cur;
	}

	return NULL;
}

static int
sj_filter_json_multival(struct blob_buf *buf, struct blob_attr *data,
			struct blob_attr *key, int key_len)
{
	struct blob_attr *cur, *cur_key = key;
	int rem, ret = SC_ERR_NOT_FOUND;

	if (!data)
		return SC_ERR_NOT_FOUND;

	if (key_len < sizeof(struct blob_attr) || key_len < blob_pad_len(key)) {
		blobmsg_add_field(buf, blobmsg_type(data), NULL,
				  blobmsg_data(data), blobmsg_data_len(data));
		return 0;
	}

	key_len -= blob_pad_len(key);
	key = blob_next(key);

	switch (blobmsg_type(cur_key)) {
	case BLOBMSG_TYPE_BOOL:
		blobmsg_for_each_attr(cur, data, rem) {
			if (!sj_filter_json_multival(buf, cur, key, key_len))
				ret = 0;

			if (!blobmsg_get_bool(cur_key))
				break;
		}
		return ret;
	case BLOBMSG_TYPE_STRING:
		cur = __sj_filter_json_table(data, blobmsg_data(cur_key));
		return sj_filter_json_multival(buf, cur, key, key_len);
	default:
		return SC_ERR_INVALID_ARGUMENT;
	}
}

int sj_filter_json(struct blob_buf *buf, struct blob_attr *data,
		   const struct blob_attr *key, const char *select)
{
	const struct blob_attr *cur;
	bool initial = true;
	int rem;

	if (!key)
		return SC_ERR_INVALID_ARGUMENT;

	if (!select)
		select = "value";

	if (blobmsg_type(key) == BLOBMSG_TYPE_STRING) {
		data = __sj_filter_json_table(data, blobmsg_data(key));
		goto out;
	}

	if (blobmsg_type(key) != BLOBMSG_TYPE_ARRAY)
		return SC_ERR_INVALID_ARGUMENT;

	if (!strcmp(select, "multival")) {
		void *c;
		int ret;

		c = blobmsg_open_array(buf, "value");
		ret = sj_filter_json_multival(buf, data, blobmsg_data(key),
					       blobmsg_data_len(key));
		blobmsg_close_array(buf, c);

		return ret;
	}

	if (blobmsg_check_array(key, BLOBMSG_TYPE_STRING) < 0)
		return SC_ERR_INVALID_ARGUMENT;

	blobmsg_for_each_attr(cur, key, rem) {
		int type = BLOBMSG_TYPE_TABLE;

		if (!initial)
			type = blobmsg_type(data);

		switch (type) {
		case BLOBMSG_TYPE_TABLE:
			data = __sj_filter_json_table(data, blobmsg_data(cur));
			initial = false;
			break;
		default:
			data = NULL;
			break;
		}
		if (!data)
			break;
	}

out:
	if (!data)
		return SC_ERR_NOT_FOUND;

	if (!strcmp(select, "value")) {
		blobmsg_add_field(buf, blobmsg_type(data), "value",
				  blobmsg_data(data), blobmsg_data_len(data));
	} else if (!strcmp(select, "keys")) {
		struct blob_attr *cur;
		void *c;
		int rem;

		if (!initial && blobmsg_type(data) != BLOBMSG_TYPE_TABLE)
			return SC_ERR_NOT_FOUND;

		c = blobmsg_open_array(buf, "value");
		blobmsg_for_each_attr(cur, data, rem)
			blobmsg_add_string(buf, NULL, blobmsg_name(cur));
		blobmsg_close_array(buf, c);
	}

	return 0;
}
