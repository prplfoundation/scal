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
#include <stdlib.h>
#include "scapi_json.h"

enum {
	MAP_VALUES,
	MAP_DEFAULT,
	__MAP_MAX,
};

static const struct blobmsg_policy filter_map_policy[__MAP_MAX] = {
	[MAP_VALUES] = { "values", BLOBMSG_TYPE_ARRAY },
	[MAP_DEFAULT] = { "default", BLOBMSG_TYPE_STRING },
};

static const char *
sj_filter_map_val(struct blob_attr *data, const char *key, bool get)
{
	static const struct blobmsg_policy policy[] = {
		{ NULL, BLOBMSG_TYPE_STRING },
		{ NULL, BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *cur;
	struct blob_attr *tb[2];
	int rem;

	blobmsg_for_each_attr(cur, data, rem) {
		blobmsg_parse_array(policy, 2, tb, blobmsg_data(cur), blobmsg_data_len(cur));
		if (!tb[0] || !tb[1])
			continue;

		if (strcmp(blobmsg_get_string(tb[get]), key) != 0)
			continue;

		return blobmsg_get_string(tb[!get]);
	}

	return NULL;
}

static int
sj_filter_map_convert(struct blob_attr *data, const char *val,
		 struct blob_buf *buf, bool get)
{
	struct blob_attr *tb[__MAP_MAX];

	if (!data)
		return SC_ERR_INVALID_ARGUMENT;

	blobmsg_parse(filter_map_policy, __MAP_MAX, tb, blobmsg_data(data), blobmsg_data_len(data));
	if (!tb[MAP_VALUES])
		return SC_ERR_INVALID_ARGUMENT;

	val = sj_filter_map_val(tb[MAP_VALUES], val, get);
	if (!val) {
		if (get && tb[MAP_DEFAULT])
			val = blobmsg_get_string(tb[MAP_DEFAULT]);
		else if (!get)
			return SC_ERR_INVALID_ARGUMENT;
		else
			return SC_ERR_NOT_FOUND;
	}

	blobmsg_add_string(buf, "value", val);
	return 0;
}

static int
sj_filter_map_get(struct sj_filter *f, struct blob_attr *data,
	     struct blob_attr *val, struct blob_buf *buf)
{
	if (blobmsg_type(val) != BLOBMSG_TYPE_STRING)
		return SC_ERR_INVALID_ARGUMENT;

	return sj_filter_map_convert(data, blobmsg_get_string(val), buf, true);
}

static int
sj_filter_map_set(struct sj_filter *f, struct blob_attr *data,
	     const char *val, struct blob_buf *buf)
{

	return sj_filter_map_convert(data, val, buf, false);
}

struct sj_filter sj_map = {
	.get = sj_filter_map_get,
	.set = sj_filter_map_set,
};

static void __constructor
sj_filter_map_init(void)
{
	sj_filter_add(&sj_map, "map");
}
