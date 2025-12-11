#include "app_utils.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <zephyr/sys/base64.h>

bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
	size_t len = strlen(hex);

	if (len != out_len * 2)
	{
		return false;
	}

	for (size_t i = 0; i < out_len; i++)
	{
		char byte_str[3] = {hex[i * 2], hex[i * 2 + 1], 0};
		char *end = NULL;
		long v = strtol(byte_str, &end, 16);
		if (end == byte_str || v < 0 || v > 0xFF)
		{
			return false;
		}
		out[i] = (uint8_t)v;
	}

	return true;
}

int base64_decode_str(const char *b64, uint8_t *out, size_t out_size, size_t *out_len)
{
	int ret = base64_decode(out, out_size, out_len, (const uint8_t *)b64, strlen(b64));

	return ret == 0 ? 0 : -EINVAL;
}

bool json_extract_string(const char *json, const char *key, char *out, size_t out_len)
{
	const char *pos = strstr(json, key);

	if (!pos)
	{
		return false;
	}

	pos = strchr(pos, ':');
	if (!pos)
	{
		return false;
	}

	pos = strchr(pos, '"');
	if (!pos)
	{
		return false;
	}
	pos++;

	const char *end = strchr(pos, '"');
	if (!end)
	{
		return false;
	}

	size_t len = end - pos;
	if (len + 1 > out_len)
	{
		return false;
	}

	memcpy(out, pos, len);
	out[len] = '\0';
	return true;
}

bool json_extract_uint(const char *json, const char *key, uint32_t *out)
{
	const char *pos = strstr(json, key);

	if (!pos)
	{
		return false;
	}

	pos = strchr(pos, ':');
	if (!pos)
	{
		return false;
	}
	pos++;

	while (*pos == ' ' || *pos == '\t')
	{
		pos++;
	}

	char *end = NULL;
	long v = strtol(pos, &end, 10);
	if (end == pos || v < 0)
	{
		return false;
	}

	*out = (uint32_t)v;
	return true;
}

void notify_json(struct bt_conn *conn, const struct bt_gatt_attr *attr,
				 const char *json, uint8_t notify_flag)
{
	if (!conn || notify_flag != BT_GATT_CCC_NOTIFY)
	{
		return;
	}

	bt_gatt_notify(conn, attr, json, strlen(json));
}
