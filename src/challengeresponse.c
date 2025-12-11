#include "BLECore.h"
#include "app_config.h"
#include "app_utils.h"
#include "challengeresponse.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <zephyr/sys/printk.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <mbedtls/md.h>

static uint8_t device_secret[32];
static const struct bt_gatt_attr *challenge_attr;
static uint8_t challenge_notify_enabled;
static char last_challenge[96];

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

int challenge_load_device_secret(void)
{
	if (!hex_to_bytes(DEVICE_SECRET_HEX, device_secret, sizeof(device_secret)))
	{
		printk("Failed to parse device secret\n");
		return -EINVAL;
	}

	return 0;
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

ssize_t response_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
					   const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
	ARG_UNUSED(attr);
	ARG_UNUSED(offset);
	ARG_UNUSED(flags);

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

	uint8_t expected_mac[32];
	if (!session.challenge_sent)
	{
		return len;
	}

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
}
