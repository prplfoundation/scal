/*
 * Copyright (C) 2016 prpl Foundation
 * Written by Felix Fietkau <nbd@nbd.name>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <uci.h>
#include "scapi_json.h"

struct uci_session {
	struct sj_session acs;

	struct uci_context *ctx;
	bool local_confdir;
};

enum {
	UCI_A_MODE,
	UCI_A_PACKAGE,
	UCI_A_SECTION,
	UCI_A_SECTION_TYPE,
	UCI_A_SECTION_OPTIONS,
	UCI_A_OPTION,
	UCI_A_LIST_ITEM,
	UCI_A_REQUIRED,
	__UCI_A_MAX,
};

static const struct blobmsg_policy uci_policy[__UCI_A_MAX] = {
	[UCI_A_MODE] = { "mode", BLOBMSG_TYPE_STRING },
	[UCI_A_PACKAGE] = { "package", BLOBMSG_TYPE_STRING },
	[UCI_A_SECTION] = { "section", BLOBMSG_TYPE_STRING },
	[UCI_A_SECTION_TYPE] = { "section_type", BLOBMSG_TYPE_STRING },
	[UCI_A_SECTION_OPTIONS] = { "section_options", BLOBMSG_TYPE_TABLE },
	[UCI_A_OPTION] = { "option", BLOBMSG_TYPE_STRING },
	[UCI_A_LIST_ITEM] = { "list_item", BLOBMSG_TYPE_INT32 },
	[UCI_A_REQUIRED] = { "required", BLOBMSG_TYPE_BOOL },
};

static struct blob_buf b;

static inline struct uci_session *sj_to_uci(struct sj_session *s)
{
	return container_of(s, struct uci_session, acs);
}

static struct sj_session *uci_backend_session_alloc(struct sj_backend *ctx)
{
	struct uci_context *uci;
	struct uci_session *s;
	const char *confdir;

	uci = uci_alloc_context();
	if (!uci)
		return NULL;

	confdir = cb->option_get("uci_confdir");
	if (confdir)
		uci_set_confdir(uci, confdir);

	s = calloc(1, sizeof(*s));
	s->ctx = uci;
	s->local_confdir = confdir;

	return &s->acs;
}

static void uci_backend_session_free(struct sj_backend *ctx, struct sj_session *as)
{
	struct uci_session *s = sj_to_uci(as);

	uci_free_context(s->ctx);
	free(s);
}

static int uci_backend_fill_ptr(struct blob_attr **tb, struct uci_context *ctx, struct uci_ptr *ptr)
{
	if (!tb[UCI_A_PACKAGE] || !tb[UCI_A_SECTION] || !tb[UCI_A_OPTION])
		return SC_ERR_INVALID_ARGUMENT;

	memset(ptr, 0, sizeof(*ptr));

	ptr->package = blobmsg_data(tb[UCI_A_PACKAGE]);
	ptr->section = blobmsg_data(tb[UCI_A_SECTION]);
	ptr->option = blobmsg_data(tb[UCI_A_OPTION]);
	ptr->target = UCI_TYPE_OPTION;
	if (ptr->section[0] == '@')
		ptr->flags = UCI_LOOKUP_EXTENDED;

	if (uci_lookup_ptr(ctx, ptr, NULL, true))
		return SC_ERR_NOT_FOUND;

	return 0;
}

static int
uci_backend_get_default(struct uci_session *s, struct blob_attr **tb, struct blob_buf *buf)
{
	struct blob_attr *cur;
	struct uci_ptr ptr;
	const char *value = NULL;
	bool required = false;
	int ret;

	if ((cur = tb[UCI_A_REQUIRED]))
		required = blobmsg_get_bool(cur);

	ret = uci_backend_fill_ptr(tb, s->ctx, &ptr);
	if (ret)
		return ret;

	if (!ptr.s)
		return SC_ERR_NOT_FOUND;

	if (!ptr.o)
		goto out;

	if ((cur = tb[UCI_A_LIST_ITEM])) {
		struct uci_element *e;
		int idx = blobmsg_get_u32(cur);

		if (idx < 0)
			return SC_ERR_INVALID_ARGUMENT;

		if (ptr.o->type == UCI_TYPE_STRING) {
			if (!idx)
				value = ptr.o->v.string;

			goto out;
		}

		uci_foreach_element(&ptr.o->v.list, e) {
			if (idx-- > 0)
				continue;

			value = e->name;
			goto out;
		}
	} else {
		value = ptr.o->v.string;
	}

out:
	if (!value && required)
		return SC_ERR_NOT_FOUND;

	blobmsg_add_string(buf, "value", value ? value : "");
	return 0;
}

static int
uci_backend_set_default(struct uci_session *s, struct blob_attr **tb, const char *value)
{
	struct blob_attr *cur;
	struct uci_ptr ptr;
	int ret;

	ret = uci_backend_fill_ptr(tb, s->ctx, &ptr);
	if (ret)
		return ret;

	if (!ptr.s)
		return SC_ERR_NOT_FOUND;

	if ((cur = tb[UCI_A_LIST_ITEM])) {
		struct uci_element *e;
		int idx = blobmsg_get_u32(cur);
		int cidx = 0;
		int rem;

		if (idx < 0)
			return SC_ERR_INVALID_ARGUMENT;

		blob_buf_init(&b, 0);
		if (ptr.o->type == UCI_TYPE_STRING) {
			blobmsg_add_string(&b, NULL, cidx == idx ? value : ptr.o->v.string);
			cidx++;
		} else {
			uci_foreach_element(&ptr.o->v.list, e) {
				blobmsg_add_string(&b, NULL, cidx == idx ? value : e->name);
				cidx++;
			}
		}

		while (cidx < idx) {
			blobmsg_add_string(&b, NULL, "");
			cidx++;
		}

		if (cidx == idx)
			blobmsg_add_string(&b, NULL, value);

		cidx = 0;
		blobmsg_for_each_attr(cur, b.head, rem) {
			ptr.value = blobmsg_data(cur);
			if (!cidx)
				ret = uci_set(s->ctx, &ptr);
			else
				ret = uci_add_list(s->ctx, &ptr);
			cidx++;

			if (ret)
				break;
		}
	} else {
		ptr.value = value;
		ret = uci_set(s->ctx, &ptr);
	}

	if (ret)
		return SC_ERR_UPDATE_FAILED;

	return 0;
}

static bool
uci_match_section(struct uci_context *ctx, struct uci_section *s,
		  struct blob_attr *options)
{
	struct blob_attr *cur;
	int rem;

	if (!options)
		return true;

	blobmsg_for_each_attr(cur, options, rem) {
		const char *name, *val;

		name = blobmsg_name(cur);
		val = uci_lookup_option_string(ctx, s, name);
		if (!val)
			return false;

		if (strcmp(val, blobmsg_get_string(cur)) != 0)
			return false;
	}

	return true;
}

static int
uci_backend_find_section(struct uci_session *s, struct blob_attr **tb, struct blob_buf *buf)
{
	struct blob_attr *cur;
	const char *type, *package;
	struct uci_package *p;
	struct uci_element *e;
	void *c;
	int type_idx = 0;

	if (!tb[UCI_A_SECTION_TYPE] || !tb[UCI_A_PACKAGE])
		return SC_ERR_INVALID_ARGUMENT;

	type = blobmsg_get_string(tb[UCI_A_SECTION_TYPE]);
	package = blobmsg_get_string(tb[UCI_A_PACKAGE]);

	if (uci_load(s->ctx, package, &p))
		return SC_ERR_NOT_FOUND;

	cur = tb[UCI_A_SECTION_OPTIONS];
	if (cur && blobmsg_check_array(cur, BLOBMSG_TYPE_STRING) < 0)
		return SC_ERR_INVALID_ARGUMENT;

	c = blobmsg_open_array(buf, "value");
	uci_foreach_element(&p->sections, e) {
		struct uci_section *section = uci_to_section(e);

		if (strcmp(type, section->type) != 0)
			continue;

		type_idx++;
		if (!uci_match_section(s->ctx, section, cur))
			continue;

		if (section->anonymous)
			blobmsg_printf(buf, NULL, "@%s[%d]", type, type_idx - 1);
		else
			blobmsg_add_string(buf, NULL, section->e.name);
	}
	blobmsg_close_array(buf, c);

	return 0;
}

static const struct {
	const char *name;
	int (*get)(struct uci_session *s, struct blob_attr **tb, struct blob_buf *buf);
	int (*set)(struct uci_session *s, struct blob_attr **tb, const char *value);
} modes[] = {
	{ "find_section", uci_backend_find_section, NULL },
	{ "default", uci_backend_get_default, uci_backend_set_default },
};

static int uci_backend_get_mode(struct blob_attr **tb)
{
	struct blob_attr *cur;
	const char *mode;
	int i;

	if ((cur = tb[UCI_A_MODE]))
		mode = blobmsg_get_string(cur);
	else
		mode = "default";

	for (i = 0; i < ARRAY_SIZE(modes); i++)
		if (!strcmp(modes[i].name, mode))
			return i;

	return -1;
}

static int uci_backend_get(struct sj_session *ctx, struct blob_attr *data, struct blob_buf *buf)
{
	struct uci_session *s = sj_to_uci(ctx);
	struct blob_attr *tb[__UCI_A_MAX];
	int i;

	blobmsg_parse(uci_policy, __UCI_A_MAX, tb, blobmsg_data(data), blobmsg_data_len(data));
	i = uci_backend_get_mode(tb);
	if (i < 0)
		return SC_ERR_INVALID_ARGUMENT;

	if (!modes[i].get)
		return SC_ERR_NOT_SUPPORTED;

	return modes[i].get(s, tb, buf);
}

static int uci_backend_set(struct sj_session *ctx, struct blob_attr *data, const char *value)
{
	struct uci_session *s = sj_to_uci(ctx);
	struct blob_attr *tb[__UCI_A_MAX];
	int i;

	blobmsg_parse(uci_policy, __UCI_A_MAX, tb, blobmsg_data(data), blobmsg_data_len(data));

	i = uci_backend_get_mode(tb);
	if (i < 0)
		return SC_ERR_INVALID_ARGUMENT;

	if (!modes[i].set)
		return SC_ERR_NOT_SUPPORTED;

	return modes[i].set(s, tb, value);
}

static int uci_backend_validate(struct sj_session *ctx)
{
	/* not implemented */
	return 0;
}

static int uci_backend_commit(struct sj_session *ctx)
{
	struct uci_session *s = sj_to_uci(ctx);
	struct uci_package **pkg;
	struct uci_element *e;
	int i, n_pkg = 0;

	uci_foreach_element(&s->ctx->root, e)
		n_pkg++;

	pkg = alloca(n_pkg * sizeof(*pkg));

	n_pkg = 0;
	uci_foreach_element(&s->ctx->root, e)
		pkg[n_pkg++] = uci_to_package(e);

	for (i = 0; i < n_pkg; i++)
		uci_commit(s->ctx, &pkg[i], false);

	if (!s->local_confdir)
		system("reload_config");

	return 0;
}

static struct sj_backend uci_backend = {
	.session_alloc = uci_backend_session_alloc,
	.session_free = uci_backend_session_free,

	.get = uci_backend_get,
	.set = uci_backend_set,

	.validate = uci_backend_validate,
	.commit = uci_backend_commit,
};

static void __constructor sj_uci_init(void)
{
	sj_backend_add(&uci_backend, "uci");
}
