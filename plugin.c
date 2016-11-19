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
#include <libubox/avl-cmp.h>
#include <libubox/kvlist.h>
#include <dlfcn.h>
#include <stdarg.h>
#include "scapi.h"
#include "scald.h"

static KVLIST(options, kvlist_strlen);
static AVL_TREE(models, avl_strcmp, false, NULL);

static struct scald_model *
scald_model_get(const char *name)
{
	struct scald_model *m;

	m = avl_find_element(&models, name, m, avl);
	if (m)
		return m;

	m = scald_model_new(name);
	avl_insert(&models, &m->avl);

	return m;
}

static struct scapi_model *
scald_model_add(struct scapi_plugin *p, const char *name, void *priv)
{
	struct scald_model *m;
	void *new_plugins, *new_priv;

	m = scald_model_get(name);
	if (!m)
		return NULL;

	new_plugins = realloc(m->plugins, (m->n_plugins + 1) * sizeof(*m->plugins));
	new_priv = realloc(m->plugin_priv, (m->n_plugins + 1) * sizeof(*m->plugin_priv));
	if (!new_plugins || !new_priv)
		return NULL;

	m->plugins = new_plugins;
	m->plugin_priv = new_priv;
	m->plugins[m->n_plugins] = p;
	m->plugin_priv[m->n_plugins] = priv;
	m->n_plugins++;

	return &m->scapi;
}

static void
scald_status_model(struct blob_buf *buf, struct scald_model *m)
{
	void *c;
	int i;

	c = blobmsg_open_array(buf, "plugins");
	for (i = 0; i < m->n_plugins; i++)
		blobmsg_add_string(buf, NULL, m->plugins[i]->name);
	blobmsg_close_array(buf, c);
}

void
scald_status_models_dump(struct blob_buf *buf)
{
	struct scald_model *m;

	avl_for_each_element(&models, m, avl) {
		void *c2 = blobmsg_open_table(buf, m->scapi.name);
		scald_status_model(buf, m);
		blobmsg_close_table(buf, c2);
	}

}

static const char *
scald_plugin_option_get(const char *name)
{
	return kvlist_get(&options, name);
}

static void
scald_plugin_add(struct scapi_plugin *p)
{
}

static void
scald_plugin_log_msg(struct scapi_plugin *p, enum scald_log_level level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "[%s] ", p->name);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void
scald_plugin_load(const char *path)
{
	static const struct scapi_cb cb = {
		.plugin_add = scald_plugin_add,
		.model_add = scald_model_add,
		.option_get = scald_plugin_option_get,
		.log_msg = scald_plugin_log_msg,
	};
	typeof(scapi_module_init) *init;
	void *dlh;

	dlh = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!dlh) {
		fprintf(stderr, "Failed to load plugin %s: %s\n", path, dlerror());
		return;
	}

	init = dlsym(dlh, "scapi_module_init");
	if (!init)
		return;

	init(&cb);
}

void scald_plugin_add_option(char *arg)
{
	char *val = strchr(arg, '=');

	if (!val)
		val = arg + strlen(arg);
	else
		*(val++) = 0;

	kvlist_set(&options, arg, val);
}
