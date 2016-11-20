#include <libubox/blobmsg_json.h>
#include <libubus.h>

static struct ubus_context ubus_ctx;

static int
handle_acl_event(struct ubus_context *ctx, struct ubus_object *obj,
		 struct ubus_request_data *req, const char *method,
		 struct blob_attr *msg)
{
	char *data;

	data = blobmsg_format_json(msg, true);
	fprintf(stderr, "Event(%s): %s\n", method, data);
	free(data);

	return 0;
}

static void
subscribe(void)
{
	static struct ubus_subscriber ev;
	uint32_t id;
	int ret;

	ret = ubus_lookup_id(&ubus_ctx, "scald.acl", &id);
	if (ret)
	    return;

	if (!ev.cb) {
		ev.cb = handle_acl_event;
		if (ubus_register_subscriber(&ubus_ctx, &ev)) {
			ev.cb = NULL;
			return;
		}
	}

	ubus_subscribe(&ubus_ctx, &ev, id);
}


static void
event_handler(struct ubus_context *ctx, struct ubus_event_handler *ev,
	      const char *type, struct blob_attr *msg)
{
	static const struct blobmsg_policy policy[2] = {
		{ .name = "id", .type = BLOBMSG_TYPE_INT32 },
		{ .name = "path", .type = BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[2];

	blobmsg_parse(policy, 2, tb, blob_data(msg), blob_len(msg));
	if (!tb[0] || !tb[1])
		return;

	if (strcmp(blobmsg_data(tb[1]), "scald.acl") != 0)
		return;

	subscribe();
}


static void
register_events(struct ubus_context *ctx)
{
	static struct ubus_event_handler handler = {
	    .cb = event_handler
	};

	ubus_register_event_handler(ctx, &handler, "ubus.object.add");
}

int main(int argc, char **argv)
{
	uloop_init();

	if (ubus_connect_ctx(&ubus_ctx, NULL)) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return 1;
	}

	ubus_add_uloop(&ubus_ctx);
	register_events(&ubus_ctx);
	subscribe();
	uloop_run();

	return 0;
}
