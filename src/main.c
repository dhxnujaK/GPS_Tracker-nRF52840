/*
 * Immobilizer commissioning and authentication firmware
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/base64.h>

#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

#define DEVICE_NAME CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN (sizeof(DEVICE_NAME) - 1)

/* Device identity and secrets */
#define SERIAL_KEY "IMMO-EA9F-6741"
#define NODE_ID_EXPECTED "711a67d8-d72f-4840-8191-4e103269bbb0"
#define DEVICE_SECRET_HEX "743aaac305b084b76fbdfaae76bc648adacb7713934c162451965603d2dbab02"
#define BACKEND_PUBKEY_B64 "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9n3YE1g8VmXzMz4255uFYfpN80IJK4h4UGUC0HvYzsYQK3R/Eb/7Z8dzlZdmmbKdAKK48PO3YronISUF1qCovQ=="
#define COMPANY_ID 0xFFFF

/* UUIDs */
#define BT_UUID_COMM_SVC_VAL \
	BT_UUID_128_ENCODE(0x23d7f4a1, 0x8c5e, 0x4af2, 0x91b7, 0x77c3f5a0c101)
#define BT_UUID_TOKEN_CHAR_VAL \
	BT_UUID_128_ENCODE(0x23d7f4a3, 0x8c5e, 0x4af2, 0x91b7, 0x77c3f5a0c101)
#define BT_UUID_CHALLENGE_CHAR_VAL \
	BT_UUID_128_ENCODE(0x23d7f4a4, 0x8c5e, 0x4af2, 0x91b7, 0x77c3f5a0c101)
#define BT_UUID_RESPONSE_CHAR_VAL \
	BT_UUID_128_ENCODE(0x23d7f4a5, 0x8c5e, 0x4af2, 0x91b7, 0x77c3f5a0c101)

static struct bt_uuid_128 comm_svc_uuid = BT_UUID_INIT_128(BT_UUID_COMM_SVC_VAL);
static struct bt_uuid_128 token_char_uuid = BT_UUID_INIT_128(BT_UUID_TOKEN_CHAR_VAL);
static struct bt_uuid_128 challenge_char_uuid = BT_UUID_INIT_128(BT_UUID_CHALLENGE_CHAR_VAL);
static struct bt_uuid_128 response_char_uuid = BT_UUID_INIT_128(BT_UUID_RESPONSE_CHAR_VAL);

struct session_state
{
	bool token_ok;
	bool challenge_sent;
	bool trusted;
	bool bonded;
	uint8_t nonce[16];
	size_t nonce_len;
};

static struct session_state session;
static struct bt_conn *current_conn;

static uint8_t device_secret[32];
static mbedtls_pk_context backend_pk;
static bool backend_pk_ready;

static char last_token_status[96];
static char last_challenge[96];

static uint8_t token_notify_enabled;
static uint8_t challenge_notify_enabled;
static const struct bt_gatt_attr *challenge_attr;
static uint8_t token_buf[1024];
static size_t token_buf_len;
struct frag_state
{
	size_t expected_len;
	size_t expected_frags;
	size_t received_frags;
	size_t buf_len;
};
static struct frag_state token_frag;

/* Function Declarations */
static void notify_json(struct bt_conn *conn, const struct bt_gatt_attr *attr,
						const char *json, uint8_t notify_flag);
static int send_nonce(struct bt_conn *conn, const struct bt_gatt_attr *attr);
static int verify_signature_es256(const uint8_t *payload, size_t payload_len,
								  const uint8_t *sig_der, size_t sig_len);


static const uint8_t mfg_data[] = {
	COMPANY_ID & 0xFF, (COMPANY_ID >> 8) & 0xFF,
	'I', 'M', 'M', 'O', '-', 'E', 'A', '9', 'F', '-', '6', '7', '4', '1'};

/* Advertising data */
static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_COMM_SVC_VAL),
};

static const struct bt_data sd[] = {
	BT_DATA(BT_DATA_NAME_COMPLETE, DEVICE_NAME, DEVICE_NAME_LEN),
	BT_DATA(BT_DATA_MANUFACTURER_DATA, mfg_data, sizeof(mfg_data)),
};


static const char *security_err_str(enum bt_security_err err)
{
	switch (err)
	{
	case BT_SECURITY_ERR_SUCCESS:
		return "success";
	case BT_SECURITY_ERR_AUTH_FAIL:
		return "auth_fail";
	case BT_SECURITY_ERR_PIN_OR_KEY_MISSING:
		return "pin_or_key_missing";
	case BT_SECURITY_ERR_OOB_NOT_AVAILABLE:
		return "oob_not_available";
	case BT_SECURITY_ERR_AUTH_REQUIREMENT:
		return "auth_requirement";
	case BT_SECURITY_ERR_PAIR_NOT_SUPPORTED:
		return "pair_not_supported";
	case BT_SECURITY_ERR_PAIR_NOT_ALLOWED:
		return "pair_not_allowed";
	case BT_SECURITY_ERR_INVALID_PARAM:
		return "invalid_param";
	case BT_SECURITY_ERR_KEY_REJECTED:
		return "key_rejected";
	case BT_SECURITY_ERR_UNSPECIFIED:
	default:
		return "unspecified";
	}
}

static void reset_session(void)
{
	memset(&session, 0, sizeof(session));
	memset(last_token_status, 0, sizeof(last_token_status));
	memset(last_challenge, 0, sizeof(last_challenge));
	token_buf_len = 0;
	memset(&token_frag, 0, sizeof(token_frag));
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
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

static int base64_decode_str(const char *b64, uint8_t *out, size_t out_size, size_t *out_len)
{
	int ret = base64_decode(out, out_size, out_len, (const uint8_t *)b64, strlen(b64));

	return ret == 0 ? 0 : -EINVAL;
}

static bool json_extract_string(const char *json, const char *key,
								char *out, size_t out_len)
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

static bool json_extract_uint(const char *json, const char *key, uint32_t *out)
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

static int init_backend_public_key(void)
{
	uint8_t der_buf[200];
	size_t der_len = 0;
	int ret;

	mbedtls_pk_init(&backend_pk);

	ret = base64_decode(der_buf, sizeof(der_buf), &der_len,
						(const uint8_t *)BACKEND_PUBKEY_B64, strlen(BACKEND_PUBKEY_B64));
	if (ret)
	{
		printk("Failed to decode backend public key (ret %d)\n", ret);
		return ret;
	}

	ret = mbedtls_pk_parse_public_key(&backend_pk, der_buf, der_len);
	if (ret)
	{
		printk("Failed to parse backend public key (ret %d)\n", ret);
		mbedtls_pk_free(&backend_pk);
		return -EINVAL;
	}

	backend_pk_ready = true;
	return 0;
}

static ssize_t process_token_json(struct bt_conn *conn, const struct bt_gatt_attr *attr,
								  const char *json, size_t len)
{
	/* Use static buffers to keep stack usage low */
	static char payload_b64[512];
	static char signature_b64[256];
	static uint8_t payload_buf[512];
	static uint8_t sig_buf[128];
	static char payload_json[768];
	char node_id[80];
	size_t payload_len = 0;
	size_t sig_len = 0;

	if (!json_extract_string(json, "payload", payload_b64, sizeof(payload_b64)) ||
		!json_extract_string(json, "signature", signature_b64, sizeof(signature_b64)))
	{
		printk("Token write missing payload/signature\n");
		snprintk(last_token_status, sizeof(last_token_status),
				 "{\"type\":\"PAIR_TOKEN_RESULT\",\"status\":\"ERROR\"}");
		notify_json(conn, attr, last_token_status, token_notify_enabled);
		return len;
	}

	printk("Token received (json len=%zu): payload_b64 len=%zu, sig_b64 len=%zu\n",
		   len, strlen(payload_b64), strlen(signature_b64));
	printk("Token payload_b64: %s\n", payload_b64);
	printk("Token signature_b64: %s\n", signature_b64);

	if (base64_decode_str(payload_b64, payload_buf, sizeof(payload_buf), &payload_len) ||
		base64_decode_str(signature_b64, sig_buf, sizeof(sig_buf), &sig_len))
	{
		printk("Token base64 decode failed\n");
		snprintk(last_token_status, sizeof(last_token_status),
				 "{\"type\":\"PAIR_TOKEN_RESULT\",\"status\":\"ERROR\"}");
		notify_json(conn, attr, last_token_status, token_notify_enabled);
		return len;
	}

	if (payload_len >= sizeof(payload_json))
	{
		printk("Token payload too long: %zu\n", payload_len);
		snprintk(last_token_status, sizeof(last_token_status),
				 "{\"type\":\"PAIR_TOKEN_RESULT\",\"status\":\"ERROR\"}");
		notify_json(conn, attr, last_token_status, token_notify_enabled);
		return len;
	}
	memcpy(payload_json, payload_buf, payload_len);
	payload_json[payload_len] = '\0';

	printk("Token payload JSON len=%zu: %s\n", payload_len, payload_json);

	if (!json_extract_string(payload_json, "nodeId", node_id, sizeof(node_id)) ||
		strcmp(node_id, NODE_ID_EXPECTED) != 0)
	{
		printk("Token nodeId mismatch or missing\n");
		snprintk(last_token_status, sizeof(last_token_status),
				 "{\"type\":\"PAIR_TOKEN_RESULT\",\"status\":\"ERROR\"}");
		notify_json(conn, attr, last_token_status, token_notify_enabled);
		return len;
	}

	if (verify_signature_es256((uint8_t *)payload_buf, payload_len, sig_buf, sig_len))
	{
		printk("Token signature verification failed\n");
		snprintk(last_token_status, sizeof(last_token_status),
				 "{\"type\":\"PAIR_TOKEN_RESULT\",\"status\":\"ERROR\"}");
		notify_json(conn, attr, last_token_status, token_notify_enabled);
		return len;
	}

	session.token_ok = true;
	snprintk(last_token_status, sizeof(last_token_status),
			 "{\"type\":\"PAIR_TOKEN_RESULT\",\"status\":\"OK\"}");
	notify_json(conn, attr, last_token_status, token_notify_enabled);
	printk("Token validated for node %s\n", node_id);

	if (!session.challenge_sent && challenge_attr)
	{
		int serr = send_nonce(conn, challenge_attr);
		if (serr)
		{
			printk("Failed to send nonce: %d\n", serr);
		}
	}

	return len;
}

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

static void notify_json(struct bt_conn *conn, const struct bt_gatt_attr *attr,
						const char *json, uint8_t notify_flag)
{
	if (!conn || notify_flag != BT_GATT_CCC_NOTIFY)
	{
		return;
	}

	bt_gatt_notify(conn, attr, json, strlen(json));
}

/* Session helpers */
static int send_nonce(struct bt_conn *conn, const struct bt_gatt_attr *attr)
{
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
	notify_json(conn, attr, last_challenge, challenge_notify_enabled);
	printk("Challenge sent: %s\n", last_challenge);
	return 0;
}

static ssize_t token_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
						   const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
	ARG_UNUSED(attr);

	char json[1024];
	bt_security_t sec = bt_conn_get_security(conn);

	printk("token_write called, len=%u sec_level=%u\n", len, sec);

	if (sec < BT_SECURITY_L2)
	{
		printk("token_write: security below L2, requesting upgrade\n");
		/* Request encryption and ask the client to retry */
		(void)bt_conn_set_security(conn, BT_SECURITY_L2);
		return BT_GATT_ERR(BT_ATT_ERR_AUTHENTICATION);
	}

	if (flags & BT_GATT_WRITE_FLAG_PREPARE)
	{
		if (offset + len > sizeof(token_buf))
		{
			printk("token_write prepare overflow offset=%u len=%u\n", offset, len);
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
		}
		memcpy(token_buf + offset, buf, len);
		token_buf_len = MAX(token_buf_len, offset + len);
		printk("token_write prepare offset=%u len=%u total=%zu\n", offset, len, token_buf_len);
		return len;
	}

	if (flags & BT_GATT_WRITE_FLAG_EXECUTE)
	{
		/* Execute long write */
		len = token_buf_len;
		if (len == 0 || len >= sizeof(json))
		{
			printk("token_write execute invalid len=%u\n", len);
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
		}
		memcpy(json, token_buf, len);
		json[len] = '\0';
		printk("token_write execute total=%u\n", len);
		token_buf_len = 0;
	}
	else
	{
		if (offset != 0)
		{
			printk("token_write with non-zero offset %u\n", offset);
			return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
		}

		if (len >= sizeof(json))
		{
			printk("token_write too long: %u\n", len);
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
			uint32_t frags = 0;
			if (!json_extract_uint(json, "len", &total_len) ||
				!json_extract_uint(json, "frags", &frags))
			{
				printk("FRAG_HDR missing len/frags\n");
				return len;
			}
			if (total_len > sizeof(token_buf) || frags == 0)
			{
				printk("FRAG_HDR invalid total_len=%u frags=%u\n", total_len, frags);
				return len;
			}
			memset(&token_frag, 0, sizeof(token_frag));
			token_frag.expected_len = total_len;
			token_frag.expected_frags = frags;
			token_frag.buf_len = 0;
			token_buf_len = 0;
			printk("FRAG_HDR len=%u frags=%u\n", total_len, frags);
			return len;
		}
		else if (strcmp(type, "FRAG") == 0)
		{
			uint32_t seq = 0;
			char data_b64[256];
			if (!json_extract_uint(json, "seq", &seq) ||
				!json_extract_string(json, "data", data_b64, sizeof(data_b64)))
			{
				printk("FRAG missing seq/data\n");
				return len;
			}
			if (token_frag.expected_len == 0)
			{
				printk("FRAG received without header\n");
				return len;
			}
			uint8_t chunk[256];
			size_t chunk_len = 0;
			if (base64_decode_str(data_b64, chunk, sizeof(chunk), &chunk_len))
			{
				printk("FRAG base64 decode failed\n");
				return len;
			}
			if (token_frag.buf_len + chunk_len > sizeof(token_buf))
			{
				printk("FRAG overflow buf_len=%zu chunk=%zu\n", token_frag.buf_len, chunk_len);
				return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
			}
			memcpy(token_buf + token_frag.buf_len, chunk, chunk_len);
			token_frag.buf_len += chunk_len;
			token_frag.received_frags++;
			printk("FRAG seq=%u chunk=%zu total=%zu/%zu\n", seq, chunk_len,
				   token_frag.buf_len, token_frag.expected_len);

			if ((token_frag.expected_frags &&
				 token_frag.received_frags >= token_frag.expected_frags) ||
				token_frag.buf_len >= token_frag.expected_len)
			{
				size_t total = token_frag.buf_len;
				if (total >= sizeof(json))
				{
					printk("Assembled token too large: %zu\n", total);
					return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
				}
				memcpy(json, token_buf, total);
				json[total] = '\0';
				printk("FRAG complete total=%zu, processing token\n", total);
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

static ssize_t challenge_read(struct bt_conn *conn, const struct bt_gatt_attr *attr,
							  void *buf, uint16_t len, uint16_t offset)
{
	const char *resp = last_challenge;

	return bt_gatt_attr_read(conn, attr, buf, len, offset, resp, strlen(resp));
}

static ssize_t response_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
							  const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
	ARG_UNUSED(attr);
	ARG_UNUSED(offset);
	ARG_UNUSED(flags);

	char json[160];

	if (len >= sizeof(json))
	{
		printk("Response write too long: %u\n", len);
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}
	memcpy(json, buf, len);
	json[len] = '\0';

	char mac_hex[80];
	if (!json_extract_string(json, "macHex", mac_hex, sizeof(mac_hex)))
	{
		printk("Response missing macHex\n");
		return len;
	}

	uint8_t mac_bytes[32];
	if (!hex_to_bytes(mac_hex, mac_bytes, sizeof(mac_bytes)))
	{
		printk("Response macHex parse failed\n");
		return len;
	}

	uint8_t expected_mac[32];
	if (!session.challenge_sent)
	{
		printk("MAC received before challenge\n");
		return len;
	}

	if (compute_hmac_sha256(device_secret, sizeof(device_secret),
							session.nonce, session.nonce_len,
							expected_mac, sizeof(expected_mac)))
	{
		printk("HMAC compute failed\n");
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

/* CCC handlers */
static void token_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	ARG_UNUSED(attr);
	token_notify_enabled = (value == BT_GATT_CCC_NOTIFY) ? BT_GATT_CCC_NOTIFY : 0;
}

static void challenge_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	ARG_UNUSED(attr);
	challenge_notify_enabled = (value == BT_GATT_CCC_NOTIFY) ? BT_GATT_CCC_NOTIFY : 0;
}

/* GATT database */
BT_GATT_SERVICE_DEFINE(comm_svc,
					   BT_GATT_PRIMARY_SERVICE(&comm_svc_uuid),
					   BT_GATT_CHARACTERISTIC(&token_char_uuid.uuid,
											  BT_GATT_CHRC_WRITE | BT_GATT_CHRC_NOTIFY,
											  BT_GATT_PERM_WRITE,
											  NULL, token_write, NULL),
					   BT_GATT_CCC(token_ccc_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),

					   BT_GATT_CHARACTERISTIC(&challenge_char_uuid.uuid,
											  BT_GATT_CHRC_READ | BT_GATT_CHRC_NOTIFY,
											  BT_GATT_PERM_READ,
											  challenge_read, NULL, NULL),
					   BT_GATT_CCC(challenge_ccc_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),

					   BT_GATT_CHARACTERISTIC(&response_char_uuid.uuid,
											  BT_GATT_CHRC_WRITE,
											  BT_GATT_PERM_WRITE,
											  NULL, response_write, NULL), );

static void init_attr_refs(void)
{
	/* Challenge characteristic value attribute index within the service */
	challenge_attr = &comm_svc.attrs[5];
}

/* Connection callbacks */
static void connected(struct bt_conn *conn, uint8_t err)
{
	if (err)
	{
		printk("Connection failed (err %u)\n", err);
		return;
	}

	current_conn = bt_conn_ref(conn);
	reset_session();

	/* Enable notifications by default so status/nonce messages are sent even if CCC isn't set. */
	token_notify_enabled = BT_GATT_CCC_NOTIFY;
	challenge_notify_enabled = BT_GATT_CCC_NOTIFY;

	printk("Connected, requesting security level 2 (LESC)\n");

	err = bt_conn_set_security(conn, BT_SECURITY_L2);
	if (err)
	{
		if (err > 0)
		{
			printk("bt_conn_set_security failed, HCI status 0x%02x\n", err);
		}
		else
		{
			printk("bt_conn_set_security failed (err %d)\n", err);
		}
	}
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	printk("Disconnected (reason %u)\n", reason);
	if (session.bonded && !session.trusted && conn)
	{
		char addr[BT_ADDR_LE_STR_LEN];
		const bt_addr_le_t *dst = bt_conn_get_dst(conn);
		bt_addr_le_to_str(dst, addr, sizeof(addr));
		int uerr = bt_unpair(BT_ID_DEFAULT, dst);
		printk("Unpaired %s on disconnect (challenge not validated) err=%d\n", addr, uerr);
	}
	if (current_conn)
	{
		bt_conn_unref(current_conn);
		current_conn = NULL;
	}
	reset_session();
}

static enum bt_security_err pairing_accept(struct bt_conn *conn,
										   const struct bt_conn_pairing_feat *const feat);
static void security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err);

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
	.security_changed = security_changed,
};

static void auth_cancel(struct bt_conn *conn)
{
	printk("Auth request cancelled\n");
}

static enum bt_security_err pairing_accept(struct bt_conn *conn,
										   const struct bt_conn_pairing_feat *const feat)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	printk("Pairing accept from %s io_cap=%u oob=%u auth_req=0x%02x key_size=%u\n",
		   addr, feat->io_capability, feat->oob_data_flag, feat->auth_req,
		   feat->max_enc_key_size);
	return BT_SECURITY_ERR_SUCCESS;
}

static const struct bt_conn_auth_cb auth_cb = {
	.pairing_accept = pairing_accept,
	.cancel = auth_cancel,
};

static void pairing_complete(struct bt_conn *conn, bool bonded)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	session.bonded = bonded;
	printk("Pairing completed with %s (bonded=%d)\n", addr, bonded);
}

static void pairing_failed(struct bt_conn *conn, enum bt_security_err reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	session.bonded = false;
	printk("Pairing failed with %s (reason=%d:%s)\n", addr, reason,
		   security_err_str(reason));
}

static struct bt_conn_auth_info_cb auth_info_cb = {
	.pairing_complete = pairing_complete,
	.pairing_failed = pairing_failed,
};

static void security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	if (err)
	{
		printk("Security change failed with %s level %u (err %d:%s)\n", addr,
			   level, err, security_err_str(err));
	}
	else
	{
		printk("Security changed with %s level %u\n", addr, level);
	}
}

static void clear_bonds(void)
{
	int err = bt_unpair(BT_ID_DEFAULT, BT_ADDR_LE_ANY);

	if (err)
	{
		printk("Bond clear failed: %d\n", err);
	}
	else
	{
		printk("Bonds cleared\n");
	}
}

static int init_crypto_material(void)
{
	if (!hex_to_bytes(DEVICE_SECRET_HEX, device_secret, sizeof(device_secret)))
	{
		printk("Failed to parse device secret\n");
		return -EINVAL;
	}

	return init_backend_public_key();
}

int main(void)
{
	int err;

	printk("Starting immobilizer commissioning app\n");

	err = bt_enable(NULL);
	if (err)
	{
		printk("Bluetooth init failed (err %d)\n", err);
		return 0;
	}

	printk("Bluetooth initialized\n");

	if (IS_ENABLED(CONFIG_SETTINGS))
	{
		settings_load();
		printk("Settings loaded\n");
	}

	/* Clear existing bonds to avoid stale keys during development */
	clear_bonds();

	err = init_crypto_material();
	if (err)
	{
		printk("Crypto init failed (err %d)\n", err);
		return 0;
	}

	init_attr_refs();

	err = bt_conn_auth_cb_register(&auth_cb);
	if (err)
	{
		printk("Failed to register auth callbacks: %d\n", err);
		return 0;
	}

	err = bt_conn_auth_info_cb_register(&auth_info_cb);
	if (err)
	{
		printk("Failed to register auth info callbacks: %d\n", err);
		return 0;
	}

	err = bt_le_adv_start(BT_LE_ADV_CONN, ad, ARRAY_SIZE(ad), sd, ARRAY_SIZE(sd));
	if (err)
	{
		printk("Advertising failed to start (err %d)\n", err);
		return 0;
	}

	printk("Advertising started\n");

	for (;;)
	{
		k_sleep(K_SECONDS(1));
	}

	return 0;
}
