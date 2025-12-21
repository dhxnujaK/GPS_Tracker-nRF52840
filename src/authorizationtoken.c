#include "BLECore.h"
#include "app_config.h"
#include "app_utils.h"
#include "authorizationtoken.h"
#include "challengeresponse.h"

#include <string.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>

static char last_token_status[96];
static uint8_t token_notify_enabled;

static uint8_t token_buf[1024];
static size_t token_buf_len;

struct frag_state
{
	size_t expected_len;
	size_t buf_len;
};

static struct frag_state token_frag;

static void publish_token_result(struct bt_conn *conn, const struct bt_gatt_attr *attr,
								 const char *status)
{
	snprintk(last_token_status, sizeof(last_token_status),
			 "{\"type\":\"LINK_MODE_RESULT\",\"status\":\"%s\"}", status);
	notify_json(conn, attr, last_token_status, token_notify_enabled);
}

static ssize_t process_token_json(struct bt_conn *conn, const struct bt_gatt_attr *attr,
								  const char *json, size_t len)
{
	char cmd[32];
	char immobiliser_id[80];

	if (!json_extract_string(json, "cmd", cmd, sizeof(cmd)))
	{
		publish_token_result(conn, attr, "ERROR");
		return len;
	}

	if (strcmp(cmd, "ENTER_LINK_MODE") != 0)
	{
		publish_token_result(conn, attr, "ERROR");
		return len;
	}

	if (!json_extract_string(json, "immobiliserId", immobiliser_id, sizeof(immobiliser_id)))
	{
		publish_token_result(conn, attr, "ERROR");
		return len;
	}

	session.token_ok = true;
	challenge_set_expected_immobiliser_id(immobiliser_id);
	publish_token_result(conn, attr, "OK");
	printk("Link mode enabled for immobiliser %s\n", immobiliser_id);

	return len;
}

ssize_t token_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
					const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
	ARG_UNUSED(attr);

	char json[1024];

	if (bt_conn_get_security(conn) < BT_SECURITY_L2)
	{
		/* Request encryption and ask the client to retry */
		(void)bt_conn_set_security(conn, BT_SECURITY_L2);
		return BT_GATT_ERR(BT_ATT_ERR_AUTHENTICATION);
	}

	if (flags & BT_GATT_WRITE_FLAG_PREPARE)
	{
		if (offset + len > sizeof(token_buf))
		{
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
		}
		memcpy(token_buf + offset, buf, len);
		token_buf_len = MAX(token_buf_len, offset + len);
		return len;
	}

	if (flags & BT_GATT_WRITE_FLAG_EXECUTE)
	{
		/* Execute long write */
		len = token_buf_len;
		if (len == 0 || len >= sizeof(json))
		{
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
		}
		memcpy(json, token_buf, len);
		json[len] = '\0';
		token_buf_len = 0;
	}
	else
	{
		if (offset != 0)
		{
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
		}

		if (len >= sizeof(json))
		{
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
		}
		memcpy(json, buf, len);
		json[len] = '\0';
		token_buf_len = 0;
	}

	/* Fragmented send from app: FRAG_HDR / FRAG */
	char type[16];
	if (json_extract_string(json, "type", type, sizeof(type)))
	{
		if (strcmp(type, "FRAG_HDR") == 0)
		{
			uint32_t total_len = 0;
			if (!json_extract_uint(json, "len", &total_len))
			{
				return len;
			}
			if (total_len == 0 || total_len > sizeof(token_buf))
			{
				return len;
			}
			memset(&token_frag, 0, sizeof(token_frag));
			token_frag.expected_len = total_len;
			token_frag.buf_len = 0;
			token_buf_len = 0;
			return len;
		}
		else if (strcmp(type, "FRAG") == 0)
		{
			char data_b64[256];
			if (!json_extract_string(json, "data", data_b64, sizeof(data_b64)))
			{
				return len;
			}
			if (token_frag.expected_len == 0)
			{
				return len;
			}
			uint8_t chunk[256];
			size_t chunk_len = 0;
			if (base64_decode_str(data_b64, chunk, sizeof(chunk), &chunk_len))
			{
				return len;
			}
			if (token_frag.buf_len + chunk_len > sizeof(token_buf))
			{
				return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
			}
			memcpy(token_buf + token_frag.buf_len, chunk, chunk_len);
			token_frag.buf_len += chunk_len;

			if (token_frag.buf_len >= token_frag.expected_len)
			{
				size_t total = token_frag.buf_len;
				if (total >= sizeof(json))
				{
					return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
				}
				memcpy(json, token_buf, total);
				json[total] = '\0';
				memset(&token_frag, 0, sizeof(token_frag));
				token_buf_len = 0;
				return process_token_json(conn, attr, json, total);
			}
			return len;
		}
	}

	/* Non-fragmented path: process directly */
	return process_token_json(conn, attr, json, len);
}

void token_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	ARG_UNUSED(attr);
	token_notify_enabled = (value == BT_GATT_CCC_NOTIFY) ? BT_GATT_CCC_NOTIFY : 0;
}

void token_force_notify_enable(void)
{
	token_notify_enabled = BT_GATT_CCC_NOTIFY;
}

void token_reset(void)
{
	memset(last_token_status, 0, sizeof(last_token_status));
	memset(&token_frag, 0, sizeof(token_frag));
	token_notify_enabled = 0;
	token_buf_len = 0;
}
