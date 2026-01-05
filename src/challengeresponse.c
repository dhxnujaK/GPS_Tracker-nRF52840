#include "BLECore.h"
#include "app_config.h"
#include "app_utils.h"
#include "challengeresponse.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/settings/settings.h>
#include <mbedtls/md.h>

static uint8_t device_secret[32];
static const struct bt_gatt_attr *challenge_attr;
static uint8_t challenge_notify_enabled;
static char last_challenge[160];
static char linked_keyfob_id[80];
static char expected_keyfob_id[80];
static uint8_t link_key[32];
static bool link_key_set;
static uint8_t link_nonce[16];
static size_t link_nonce_len;
struct frag_state
{
	size_t expected_len;
	size_t buf_len;
};
static uint8_t response_buf[256];
static char response_cmd_buf[128];
static struct frag_state response_frag;

static int settings_set(const char *name, size_t len,
						settings_read_cb read_cb, void *cb_arg)
{
	if (strcmp(name, LINKED_KEYFOB_SETTINGS_KEY) == 0)
	{
		size_t copy_len = MIN(len, sizeof(linked_keyfob_id) - 1);
		ssize_t r = read_cb(cb_arg, linked_keyfob_id, copy_len);
		if (r > 0)
		{
			linked_keyfob_id[r] = '\0';
		}
		return 0;
	}

	return -ENOENT;
}

static struct settings_handler link_settings = {
	.name = "immo",
	.h_set = settings_set,
};

static int save_linked_keyfob_id(const char *id)
{
	return settings_save_one("immo/" LINKED_KEYFOB_SETTINGS_KEY, id, strlen(id));
}

static int compute_hmac_sha256(const uint8_t *key, size_t key_len,
							   const uint8_t *msg, size_t msg_len,
							   uint8_t *out_mac, size_t out_size)
{
	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	unsigned char mac[32];

	if (!md_info || out_size < sizeof(mac))
	{
		return -EINVAL;
	}

	int ret = mbedtls_md_hmac(md_info, key, key_len, msg, msg_len, mac);
	if (ret)
	{
		return -EINVAL;
	}

	memcpy(out_mac, mac, sizeof(mac));
	return 0;
}

static void format_hex(const uint8_t *in, size_t len, char *out, size_t out_len)
{
	if (out_len < (len * 2 + 1))
	{
		return;
	}

	for (size_t i = 0; i < len; i++)
	{
		snprintf(&out[i * 2], 3, "%02x", in[i]);
	}
}

static void format_hex32(const uint8_t *in, char *out, size_t out_len)
{
	format_hex(in, 32, out, out_len);
}

static void format_hex16(const uint8_t *in, char *out, size_t out_len)
{
	format_hex(in, 16, out, out_len);
}

int challenge_set_link_key_hex(const char *hex)
{
	if (!hex || !hex[0])
	{
		return -EINVAL;
	}

	if (!hex_to_bytes(hex, link_key, sizeof(link_key)))
	{
		return -EINVAL;
	}

	link_key_set = true;
	return 0;
}

void challenge_get_last_json(const char **json, size_t *len)
{
	if (json)
	{
		*json = last_challenge;
	}
	if (len)
	{
		*len = strlen(last_challenge);
	}
}

int challenge_load_device_secret(void)
{
	if (!hex_to_bytes(DEVICE_SECRET_HEX, device_secret, sizeof(device_secret)))
	{
		printk("Failed to parse device secret\n");
		return -EINVAL;
	}

	return 0;
}

int challenge_settings_init(void)
{
	if (!IS_ENABLED(CONFIG_SETTINGS))
	{
		return 0;
	}

	return settings_register(&link_settings);
}

void challenge_set_attr(const struct bt_gatt_attr *attr)
{
	challenge_attr = attr;
}

int challenge_send_nonce(struct bt_conn *conn)
{
	if (!challenge_attr)
	{
		return -EINVAL;
	}

	int ret;
	uint8_t nonce[16];

	ret = sys_csrand_get(nonce, sizeof(nonce));
	if (ret)
	{
		return -EIO;
	}

	memcpy(session.nonce, nonce, sizeof(nonce));
	session.nonce_len = sizeof(nonce);
	session.challenge_sent = true;
	if (expected_keyfob_id[0])
	{
		memcpy(link_nonce, nonce, sizeof(nonce));
		link_nonce_len = sizeof(nonce);
	}

	char nonce_hex[16 * 2 + 1];
	for (size_t i = 0; i < sizeof(nonce); i++)
	{
		snprintf(&nonce_hex[i * 2], 3, "%02x", nonce[i]);
	}

	snprintk(last_challenge, sizeof(last_challenge),
			 "{\"nonceHex\":\"%s\"}", nonce_hex);
	notify_json(conn, challenge_attr, last_challenge, challenge_notify_enabled);
	printk("Challenge sent\n");
	return 0;
}

ssize_t challenge_read(struct bt_conn *conn, const struct bt_gatt_attr *attr,
					   void *buf, uint16_t len, uint16_t offset)
{
	const char *resp = last_challenge;

	return bt_gatt_attr_read(conn, attr, buf, len, offset, resp, strlen(resp));
}

static int verify_response_json(struct bt_conn *notify_conn, const char *json)
{
	char mac_hex[80];
	if (!json_extract_string(json, "macHex", mac_hex, sizeof(mac_hex)))
	{
		return -EINVAL;
	}

	char keyfob_id[80] = {0};
	bool has_keyfob_id = json_extract_string(json, "keyfobNodeId",
											 keyfob_id, sizeof(keyfob_id));
	if (expected_keyfob_id[0])
	{
		if (!has_keyfob_id || strcmp(keyfob_id, expected_keyfob_id) != 0)
		{
			return -EACCES;
		}
	}

	uint8_t mac_bytes[32];
	if (!hex_to_bytes(mac_hex, mac_bytes, sizeof(mac_bytes)))
	{
		return -EINVAL;
	}

	uint8_t expected_mac[32];
	if (!session.challenge_sent)
	{
		return -EACCES;
	}

	const uint8_t *key = device_secret;
	size_t key_len = sizeof(device_secret);
	if (expected_keyfob_id[0] && link_key_set)
	{
		key = link_key;
		key_len = sizeof(link_key);
	}

	const uint8_t *msg = session.nonce;
	size_t msg_len = session.nonce_len;
	if (expected_keyfob_id[0] && link_nonce_len == sizeof(link_nonce))
	{
		msg = link_nonce;
		msg_len = link_nonce_len;
	}

	if (compute_hmac_sha256(key, key_len,
							msg, msg_len,
							expected_mac, sizeof(expected_mac)))
	{
		return -EINVAL;
	}

	char mac_hex_dbg[65];
	memset(mac_hex_dbg, 0, sizeof(mac_hex_dbg));
	format_hex32(expected_mac, mac_hex_dbg, sizeof(mac_hex_dbg));
	printk("Link HMAC expected (immo): %s\n", mac_hex_dbg);

	char key_hex_dbg[65];
	memset(key_hex_dbg, 0, sizeof(key_hex_dbg));
	format_hex32(key, key_hex_dbg, sizeof(key_hex_dbg));
	printk("Link key used (immo): %s\n", key_hex_dbg);

	char nonce_hex_dbg[33];
	memset(nonce_hex_dbg, 0, sizeof(nonce_hex_dbg));
	format_hex16(msg, nonce_hex_dbg, sizeof(nonce_hex_dbg));
	printk("Link nonce used (immo): %s\n", nonce_hex_dbg);

	if (memcmp(mac_bytes, expected_mac, sizeof(expected_mac)) == 0)
	{
		session.trusted = true;
		const char *ok = "{\"status\":\"AUTH_OK\"}";
		snprintk(last_challenge, sizeof(last_challenge), "%s", ok);
		if (challenge_attr)
		{
			notify_json(notify_conn, challenge_attr, last_challenge, challenge_notify_enabled);
		}
		if (expected_keyfob_id[0] && has_keyfob_id)
		{
			strncpy(linked_keyfob_id, keyfob_id, sizeof(linked_keyfob_id));
			linked_keyfob_id[sizeof(linked_keyfob_id) - 1] = '\0';
			(void)save_linked_keyfob_id(linked_keyfob_id);
			snprintk(last_challenge, sizeof(last_challenge),
					 "{\"status\":\"LINK_OK\",\"keyfobNodeId\":\"%s\"}", linked_keyfob_id);
			if (challenge_attr)
			{
				notify_json(notify_conn, challenge_attr, last_challenge, challenge_notify_enabled);
			}
		}
		printk("Challenge response validated\n");
		return 0;
	}
	else
	{
		const char *err = "{\"status\":\"ERROR\"}";
		snprintk(last_challenge, sizeof(last_challenge), "%s", err);
		if (challenge_attr)
		{
			notify_json(notify_conn, challenge_attr, last_challenge, challenge_notify_enabled);
		}
		printk("Challenge response failed\n");
		/* Drop bond if challenge failed */
		if (session.bonded && current_conn)
		{
			char addr[BT_ADDR_LE_STR_LEN];
			const bt_addr_le_t *dst = bt_conn_get_dst(current_conn);
			bt_addr_le_to_str(dst, addr, sizeof(addr));
			int uerr = bt_unpair(BT_ID_DEFAULT, dst);
			printk("Unpaired %s after failed challenge (err=%d)\n", addr, uerr);
			session.bonded = false;
		}
	}

	return -EACCES;
}

int challenge_process_response_json(struct bt_conn *notify_conn,
									const char *json, size_t len)
{
	if (!json || len == 0)
	{
		return -EINVAL;
	}

	char tmp[160];
	size_t copy_len = MIN(len, sizeof(tmp) - 1);
	memcpy(tmp, json, copy_len);
	tmp[copy_len] = '\0';

	return verify_response_json(notify_conn, tmp);
}

ssize_t response_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
					   const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
	ARG_UNUSED(attr);
	ARG_UNUSED(offset);
	ARG_UNUSED(flags);

	if (len >= sizeof(response_buf))
	{
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}

	char type[16];
	if (len < sizeof(response_cmd_buf))
	{
		memcpy(response_cmd_buf, buf, len);
		response_cmd_buf[len] = '\0';
		if (json_extract_string(response_cmd_buf, "type", type, sizeof(type)))
		{
			if (strcmp(type, "FRAG_HDR") == 0)
			{
				uint32_t total_len = 0;
				if (!json_extract_uint(response_cmd_buf, "len", &total_len))
				{
					return len;
				}
				if (total_len == 0 || total_len >= sizeof(response_buf))
				{
					return len;
				}
				memset(&response_frag, 0, sizeof(response_frag));
				response_frag.expected_len = total_len;
				response_frag.buf_len = 0;
				return len;
			}
			else if (strcmp(type, "FRAG") == 0)
			{
				char data_b64[128];
				if (!json_extract_string(response_cmd_buf, "data", data_b64, sizeof(data_b64)))
				{
					return len;
				}
				if (response_frag.expected_len == 0)
				{
					return len;
				}
				uint8_t chunk[128];
				size_t chunk_len = 0;
				if (base64_decode_str(data_b64, chunk, sizeof(chunk), &chunk_len))
				{
					return len;
				}
				if (response_frag.buf_len + chunk_len >= sizeof(response_buf))
				{
					return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
				}
				memcpy(response_buf + response_frag.buf_len, chunk, chunk_len);
				response_frag.buf_len += chunk_len;

				if (response_frag.buf_len >= response_frag.expected_len)
				{
					size_t total = response_frag.buf_len;
					if (total >= sizeof(response_buf))
					{
						return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
					}
					response_buf[total] = '\0';
					memset(&response_frag, 0, sizeof(response_frag));
					(void)verify_response_json(conn, (char *)response_buf);
				}
				return len;
			}
		}
	}

	memcpy(response_buf, buf, len);
	response_buf[len] = '\0';
	(void)verify_response_json(conn, (char *)response_buf);
	return len;
}

void challenge_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	ARG_UNUSED(attr);
	challenge_notify_enabled = (value == BT_GATT_CCC_NOTIFY) ? BT_GATT_CCC_NOTIFY : 0;
}

void challenge_force_notify_enable(void)
{
	challenge_notify_enabled = BT_GATT_CCC_NOTIFY;
}

void challenge_reset(void)
{
	memset(last_challenge, 0, sizeof(last_challenge));
	challenge_notify_enabled = 0;
	memset(expected_keyfob_id, 0, sizeof(expected_keyfob_id));
	memset(link_key, 0, sizeof(link_key));
	link_key_set = false;
	memset(link_nonce, 0, sizeof(link_nonce));
	link_nonce_len = 0;
	memset(&response_frag, 0, sizeof(response_frag));
}

void challenge_reset_preserve_expected(void)
{
	memset(last_challenge, 0, sizeof(last_challenge));
	challenge_notify_enabled = 0;
	memset(link_nonce, 0, sizeof(link_nonce));
	link_nonce_len = 0;
	memset(&response_frag, 0, sizeof(response_frag));
}

bool challenge_link_pending(void)
{
	return expected_keyfob_id[0] != '\0';
}

void challenge_set_expected_keyfob_id(const char *id)
{
	strncpy(expected_keyfob_id, id, sizeof(expected_keyfob_id));
	expected_keyfob_id[sizeof(expected_keyfob_id) - 1] = '\0';
}
