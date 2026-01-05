#include "BLECore.h"
#include "app_config.h"
#include "app_utils.h"
#include "authorizationtoken.h"
#include "challengeresponse.h"

#include <errno.h>
#include <string.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/base64.h>
#include <zephyr/sys/util.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

static mbedtls_pk_context backend_pk;
static bool backend_pk_ready;

static char last_token_status[96];
static uint8_t token_notify_enabled;
static const struct bt_gatt_attr *token_attr;
static bool secure_ready_pending;

static uint8_t token_buf[1024];
static size_t token_buf_len;
static char token_cmd_buf[256];

struct frag_state
{
	size_t expected_len;
	size_t buf_len;
};

static struct frag_state token_frag;

static int verify_signature_es256(const uint8_t *payload, size_t payload_len,
								  const uint8_t *sig_der, size_t sig_len)
{
	if (!backend_pk_ready)
	{
		return -EFAULT;
	}

	uint8_t hash[32];
	int ret = mbedtls_sha256(payload, payload_len, hash, 0);
	if (ret)
	{
		return -EINVAL;
	}

	ret = mbedtls_pk_verify(&backend_pk, MBEDTLS_MD_SHA256, hash, sizeof(hash),
							sig_der, sig_len);
	if (ret)
	{
		return -EACCES;
	}

	return 0;
}

static void publish_token_result(struct bt_conn *conn, const struct bt_gatt_attr *attr,
								 const char *status)
{
	snprintk(last_token_status, sizeof(last_token_status),
			 "{\"type\":\"PAIR_TOKEN_RESULT\",\"status\":\"%s\"}", status);
	notify_json(conn, attr, last_token_status, token_notify_enabled);
}

static void publish_scan_result(struct bt_conn *conn, const struct bt_gatt_attr *attr,
								const char *status)
{
	snprintk(last_token_status, sizeof(last_token_status),
			 "{\"type\":\"KEYFOB_SCAN_RESULT\",\"status\":\"%s\"}", status);
	notify_json(conn, attr, last_token_status, token_notify_enabled);
}

static ssize_t process_token_json(struct bt_conn *conn, const struct bt_gatt_attr *attr,
								  const char *json, size_t len)
{
	char cmd[32];
	char cmd_keyfob_id[80];

	if (json_extract_string(json, "cmd", cmd, sizeof(cmd)))
	{
		if (strcmp(cmd, "START_KEYFOB_SCAN") == 0)
		{
			if (json_extract_string(json, "keyfobNodeId",
									cmd_keyfob_id, sizeof(cmd_keyfob_id)))
			{
				challenge_set_expected_keyfob_id(cmd_keyfob_id);
				(void)ble_link_keyfob_start(cmd_keyfob_id);
				publish_scan_result(conn, attr, "OK");
				return len;
			}
			publish_scan_result(conn, attr, "ERROR");
			return len;
		}
	}

	/* Use static buffers to keep stack usage low */
	static char payload_b64[512];
	static char signature_b64[256];
	static uint8_t payload_buf[512];
	static uint8_t sig_buf[128];
	static char payload_json[768];
	char immob_id[80];
	char keyfob_id[80];
	char link_key_hex[80];
	size_t payload_len = 0;
	size_t sig_len = 0;

	if (!json_extract_string(json, "payload", payload_b64, sizeof(payload_b64)) ||
		!json_extract_string(json, "signature", signature_b64, sizeof(signature_b64)))
	{
		publish_token_result(conn, attr, "ERROR");
		return len;
	}

	if (base64_decode_str(payload_b64, payload_buf, sizeof(payload_buf), &payload_len) ||
		base64_decode_str(signature_b64, sig_buf, sizeof(sig_buf), &sig_len))
	{
		publish_token_result(conn, attr, "ERROR");
		return len;
	}

	if (payload_len >= sizeof(payload_json))
	{
		publish_token_result(conn, attr, "ERROR");
		return len;
	}
	memcpy(payload_json, payload_buf, payload_len);
	payload_json[payload_len] = '\0';

	if (json_extract_string(payload_json, "immobiliserNodeId", immob_id, sizeof(immob_id)))
	{
		if (strcmp(immob_id, NODE_ID_EXPECTED) != 0)
		{
			publish_token_result(conn, attr, "ERROR");
			return len;
		}
	}
	else if (json_extract_string(payload_json, "nodeId", immob_id, sizeof(immob_id)))
	{
		if (strcmp(immob_id, NODE_ID_EXPECTED) != 0)
		{
			publish_token_result(conn, attr, "ERROR");
			return len;
		}
	}
	else
	{
		publish_token_result(conn, attr, "ERROR");
		return len;
	}

	bool has_keyfob_id = json_extract_string(payload_json, "keyfobNodeId",
											 keyfob_id, sizeof(keyfob_id));
	if (has_keyfob_id)
	{
		challenge_set_expected_keyfob_id(keyfob_id);
		bool has_link_key = json_extract_string(payload_json, "linkKeyHex",
												link_key_hex, sizeof(link_key_hex));
		if (!has_link_key || challenge_set_link_key_hex(link_key_hex))
		{
			publish_token_result(conn, attr, "ERROR");
			return len;
		}
		printk("Link key received: %s\n", link_key_hex);
	}

	if (verify_signature_es256((uint8_t *)payload_buf, payload_len, sig_buf, sig_len))
	{
		publish_token_result(conn, attr, "ERROR");
		return len;
	}

	session.token_ok = true;
	publish_token_result(conn, attr, "OK");
	printk("Token validated for immobiliser %s\n", immob_id);

	if (has_keyfob_id)
	{
		printk("Starting keyfob scan for %s\n", keyfob_id);
		(void)ble_link_keyfob_start(keyfob_id);
	}
	else if (!session.challenge_sent)
	{
		int serr = challenge_send_nonce(conn);
		if (serr)
		{
			printk("Nonce send failed\n");
		}
	}

	return len;
}

int auth_init_backend_public_key(void)
{
	uint8_t der_buf[200];
	size_t der_len = 0;
	int ret;

	mbedtls_pk_init(&backend_pk);

	ret = base64_decode(der_buf, sizeof(der_buf), &der_len,
						(const uint8_t *)BACKEND_PUBKEY_B64, strlen(BACKEND_PUBKEY_B64));
	if (ret)
	{
		printk("Backend public key decode failed\n");
		return ret;
	}

	ret = mbedtls_pk_parse_public_key(&backend_pk, der_buf, der_len);
	if (ret)
	{
		printk("Backend public key parse failed\n");
		mbedtls_pk_free(&backend_pk);
		return -EINVAL;
	}

	backend_pk_ready = true;
	return 0;
}

ssize_t token_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
					const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
	ARG_UNUSED(attr);
	char *json = (char *)token_buf;

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
		if (len == 0 || len >= sizeof(token_buf))
		{
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
		}
		token_buf[len] = '\0';
		token_buf_len = 0;
	}
	else
	{
		if (offset != 0)
		{
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
		}

		if (len >= sizeof(token_buf))
		{
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
		}
	}

	/* Fragmented send from app: FRAG_HDR / FRAG */
	char type[16];
	if (!(flags & BT_GATT_WRITE_FLAG_EXECUTE))
	{
		if (len >= sizeof(token_cmd_buf))
		{
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
		}
		memcpy(token_cmd_buf, buf, len);
		token_cmd_buf[len] = '\0';
		if (json_extract_string(token_cmd_buf, "type", type, sizeof(type)))
		{
			if (strcmp(type, "FRAG_HDR") == 0)
			{
				uint32_t total_len = 0;
				if (!json_extract_uint(token_cmd_buf, "len", &total_len))
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
				if (!json_extract_string(token_cmd_buf, "data", data_b64, sizeof(data_b64)))
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
					if (total >= sizeof(token_buf))
					{
						return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
					}
					token_buf[total] = '\0';
					memset(&token_frag, 0, sizeof(token_frag));
					token_buf_len = 0;
					return process_token_json(conn, attr, (char *)token_buf, total);
				}
				return len;
			}
		}
	}

	if (!(flags & BT_GATT_WRITE_FLAG_EXECUTE))
	{
		memcpy(token_buf, buf, len);
		token_buf[len] = '\0';
		token_buf_len = 0;
	}

	/* Non-fragmented path: process directly */
	return process_token_json(conn, attr, json, len);
}

void token_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	ARG_UNUSED(attr);
	token_notify_enabled = (value == BT_GATT_CCC_NOTIFY) ? BT_GATT_CCC_NOTIFY : 0;
	printk("Token CCC changed: notify=%u\n", token_notify_enabled ? 1 : 0);
	if (token_notify_enabled == BT_GATT_CCC_NOTIFY && secure_ready_pending && current_conn)
	{
		printk("Token CCC ready, sending SECURE_READY\n");
		secure_ready_pending = false;
		token_notify_secure_ready(current_conn);
	}
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
	secure_ready_pending = false;
}

void token_set_attr(const struct bt_gatt_attr *attr)
{
	token_attr = attr;
}

void token_notify_secure_ready(struct bt_conn *conn)
{
	if (!token_attr || token_notify_enabled != BT_GATT_CCC_NOTIFY)
	{
		printk("SECURE_READY pending (attr=%p notify=%u)\n",
			   token_attr, token_notify_enabled ? 1 : 0);
		secure_ready_pending = true;
		return;
	}
	printk("SECURE_READY notify sent\n");
	snprintk(last_token_status, sizeof(last_token_status),
			 "{\"type\":\"SECURE_READY\",\"status\":\"OK\"}");
	notify_json(conn, token_attr, last_token_status, token_notify_enabled);
}
