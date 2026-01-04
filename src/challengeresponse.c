#include "BLECore.h"
#include "app_config.h"
#include "app_utils.h"
#include "challengeresponse.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/random/random.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>
#include <mbedtls/md.h>

static uint8_t device_secret[32];
static const struct bt_gatt_attr *challenge_attr;
static const struct bt_gatt_attr *response_attr;
static uint8_t challenge_notify_enabled;
static uint8_t response_notify_enabled;
static char last_challenge[96];
static char last_response[160];
static char linked_immobiliser_id[80];
static char expected_immobiliser_id[80];
static uint8_t link_key[32];
static bool link_key_set;

static int settings_set(const char *name, size_t len,
						settings_read_cb read_cb, void *cb_arg)
{
	if (strcmp(name, LINKED_IMMO_SETTINGS_KEY) == 0)
	{
		size_t copy_len = MIN(len, sizeof(linked_immobiliser_id) - 1);
		ssize_t r = read_cb(cb_arg, linked_immobiliser_id, copy_len);
		if (r > 0)
		{
			linked_immobiliser_id[r] = '\0';
			challenge_set_expected_immobiliser_id(linked_immobiliser_id);
		}
		return 0;
	}

	return -ENOENT;
}

static struct settings_handler link_settings = {
	.name = "keyfob",
	.h_set = settings_set,
};

static int save_linked_immobiliser_id(const char *id)
{
	return settings_save_one("keyfob/" LINKED_IMMO_SETTINGS_KEY, id, strlen(id));
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

	uint8_t nonce[16];
	int ret = sys_csrand_get(nonce, sizeof(nonce));
	if (ret)
	{
		return -EIO;
	}

	memcpy(session.nonce, nonce, sizeof(nonce));
	session.nonce_len = sizeof(nonce);
	session.challenge_sent = true;

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

void response_set_attr(const struct bt_gatt_attr *attr)
{
	response_attr = attr;
}

void challenge_set_expected_immobiliser_id(const char *id)
{
	strncpy(expected_immobiliser_id, id, sizeof(expected_immobiliser_id));
	expected_immobiliser_id[sizeof(expected_immobiliser_id) - 1] = '\0';
}

bool challenge_link_mode_active(void)
{
	return expected_immobiliser_id[0] != '\0';
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

ssize_t challenge_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
						const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
	ARG_UNUSED(attr);
	ARG_UNUSED(offset);
	ARG_UNUSED(flags);

	if (bt_conn_get_security(conn) < BT_SECURITY_L2)
	{
		return BT_GATT_ERR(BT_ATT_ERR_AUTHENTICATION);
	}

	if (!expected_immobiliser_id[0])
	{
		return len;
	}

	char json[128];
	if (len >= sizeof(json))
	{
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}
	memcpy(json, buf, len);
	json[len] = '\0';
	snprintf(last_challenge, sizeof(last_challenge), "%s", json);

	char nonce_hex[80];
	if (!json_extract_string(json, "nonceHex", nonce_hex, sizeof(nonce_hex)))
	{
		return len;
	}

	uint8_t nonce[16];
	if (!hex_to_bytes(nonce_hex, nonce, sizeof(nonce)))
	{
		return len;
	}

	uint8_t mac[32];
	const uint8_t *key = device_secret;
	size_t key_len = sizeof(device_secret);
	if (expected_immobiliser_id[0] && link_key_set)
	{
		key = link_key;
		key_len = sizeof(link_key);
	}

	if (compute_hmac_sha256(key, key_len,
							nonce, sizeof(nonce),
							mac, sizeof(mac)))
	{
		return len;
	}

	char mac_hex_dbg[65];
	memset(mac_hex_dbg, 0, sizeof(mac_hex_dbg));
	format_hex32(mac, mac_hex_dbg, sizeof(mac_hex_dbg));
	printk("Link HMAC (keyfob): %s\n", mac_hex_dbg);

	char key_hex_dbg[65];
	memset(key_hex_dbg, 0, sizeof(key_hex_dbg));
	format_hex32(key, key_hex_dbg, sizeof(key_hex_dbg));
	printk("Link key used (keyfob): %s\n", key_hex_dbg);

	char nonce_hex_dbg[33];
	memset(nonce_hex_dbg, 0, sizeof(nonce_hex_dbg));
	format_hex16(nonce, nonce_hex_dbg, sizeof(nonce_hex_dbg));
	printk("Link nonce used (keyfob): %s\n", nonce_hex_dbg);

	char mac_hex[65];
	memset(mac_hex, 0, sizeof(mac_hex));
	format_hex(mac, sizeof(mac), mac_hex, sizeof(mac_hex));
	snprintk(last_response, sizeof(last_response),
			 "{\"macHex\":\"%s\",\"keyfobNodeId\":\"%s\"}",
			 mac_hex, NODE_ID_EXPECTED);

	if (response_attr)
	{
		notify_json(conn, response_attr, last_response, response_notify_enabled);
	}

	if (expected_immobiliser_id[0])
	{
		strncpy(linked_immobiliser_id, expected_immobiliser_id, sizeof(linked_immobiliser_id));
		linked_immobiliser_id[sizeof(linked_immobiliser_id) - 1] = '\0';
		(void)save_linked_immobiliser_id(linked_immobiliser_id);
	}

	session.trusted = true;
	printk("Link response sent to immobiliser %s\n", expected_immobiliser_id);
	return len;
}

ssize_t challenge_read(struct bt_conn *conn, const struct bt_gatt_attr *attr,
					   void *buf, uint16_t len, uint16_t offset)
{
	return bt_gatt_attr_read(conn, attr, buf, len, offset,
							 last_challenge, strlen(last_challenge));
}

ssize_t response_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
					   const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
	ARG_UNUSED(attr);
	ARG_UNUSED(offset);
	ARG_UNUSED(flags);

	if (bt_conn_get_security(conn) < BT_SECURITY_L2)
	{
		return BT_GATT_ERR(BT_ATT_ERR_AUTHENTICATION);
	}

	if (challenge_link_mode_active())
	{
		return BT_GATT_ERR(BT_ATT_ERR_WRITE_NOT_PERMITTED);
	}

	char json[160];
	if (len >= sizeof(json))
	{
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}
	memcpy(json, buf, len);
	json[len] = '\0';

	char mac_hex[80];
	if (!json_extract_string(json, "macHex", mac_hex, sizeof(mac_hex)))
	{
		return len;
	}

	uint8_t mac_bytes[32];
	if (!hex_to_bytes(mac_hex, mac_bytes, sizeof(mac_bytes)))
	{
		return len;
	}

	if (!session.challenge_sent)
	{
		return len;
	}

	uint8_t expected_mac[32];
	if (compute_hmac_sha256(device_secret, sizeof(device_secret),
							session.nonce, session.nonce_len,
							expected_mac, sizeof(expected_mac)))
	{
		return len;
	}

	if (memcmp(mac_bytes, expected_mac, sizeof(expected_mac)) == 0)
	{
		session.trusted = true;
		const char *ok = "{\"status\":\"AUTH_OK\"}";
		snprintk(last_challenge, sizeof(last_challenge), "%s", ok);
		if (challenge_attr)
		{
			notify_json(conn, challenge_attr, last_challenge, challenge_notify_enabled);
		}
		printk("Challenge response validated\n");
	}
	else
	{
		const char *err = "{\"status\":\"ERROR\"}";
		snprintk(last_challenge, sizeof(last_challenge), "%s", err);
		if (challenge_attr)
		{
			notify_json(conn, challenge_attr, last_challenge, challenge_notify_enabled);
		}
		printk("Challenge response failed\n");
	}

	return len;
}

ssize_t response_read(struct bt_conn *conn, const struct bt_gatt_attr *attr,
					  void *buf, uint16_t len, uint16_t offset)
{
	return bt_gatt_attr_read(conn, attr, buf, len, offset,
							 last_response, strlen(last_response));
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

void response_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	ARG_UNUSED(attr);
	response_notify_enabled = (value == BT_GATT_CCC_NOTIFY) ? BT_GATT_CCC_NOTIFY : 0;
}

void response_force_notify_enable(void)
{
	response_notify_enabled = BT_GATT_CCC_NOTIFY;
}

void challenge_reset(void)
{
	memset(last_challenge, 0, sizeof(last_challenge));
	memset(last_response, 0, sizeof(last_response));
	memset(expected_immobiliser_id, 0, sizeof(expected_immobiliser_id));
	challenge_notify_enabled = 0;
	response_notify_enabled = 0;
	memset(link_key, 0, sizeof(link_key));
	link_key_set = false;
}

void challenge_reset_preserve_expected(void)
{
	memset(last_challenge, 0, sizeof(last_challenge));
	memset(last_response, 0, sizeof(last_response));
	challenge_notify_enabled = 0;
	response_notify_enabled = 0;
}
