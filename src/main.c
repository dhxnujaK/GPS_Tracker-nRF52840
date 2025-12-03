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

#define DEVICE_NAME             CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN         (sizeof(DEVICE_NAME) - 1)

/* Device identity and secrets */
#define SERIAL_KEY              "IMMO-EA9F-6741"
#define NODE_ID_EXPECTED        "711a67d8-d72f-4840-8191-4e103269bbb0"
#define DEVICE_SECRET_HEX       "743aaac305b084b76fbdfaae76bc648adacb7713934c162451965603d2dbab02"
#define BACKEND_PUBKEY_B64      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfMMy01z+yaSt7/Sq9ka4nxY+DEBhZVr/nksyRvcStWPRpHeGj7NGFLg3wXu1/M0bVgAvMyHPZSmZ4qffyap28w=="

/* UUIDs (replace in the app to match) */
#define BT_UUID_COMM_SVC_VAL \
	BT_UUID_128_ENCODE(0x9f87c5c1, 0x4b8b, 0x4c1c, 0x92cf, 0x27f0b2b6d001)
#define BT_UUID_OOB_CHAR_VAL \
	BT_UUID_128_ENCODE(0x9f87c5c2, 0x4b8b, 0x4c1c, 0x92cf, 0x27f0b2b6d001)
#define BT_UUID_TOKEN_CHAR_VAL \
	BT_UUID_128_ENCODE(0x9f87c5c3, 0x4b8b, 0x4c1c, 0x92cf, 0x27f0b2b6d001)
#define BT_UUID_CHALLENGE_CHAR_VAL \
	BT_UUID_128_ENCODE(0x9f87c5c4, 0x4b8b, 0x4c1c, 0x92cf, 0x27f0b2b6d001)
#define BT_UUID_RESPONSE_CHAR_VAL \
	BT_UUID_128_ENCODE(0x9f87c5c5, 0x4b8b, 0x4c1c, 0x92cf, 0x27f0b2b6d001)

static struct bt_uuid_128 comm_svc_uuid = BT_UUID_INIT_128(BT_UUID_COMM_SVC_VAL);
static struct bt_uuid_128 oob_char_uuid = BT_UUID_INIT_128(BT_UUID_OOB_CHAR_VAL);
static struct bt_uuid_128 token_char_uuid = BT_UUID_INIT_128(BT_UUID_TOKEN_CHAR_VAL);
static struct bt_uuid_128 challenge_char_uuid = BT_UUID_INIT_128(BT_UUID_CHALLENGE_CHAR_VAL);
static struct bt_uuid_128 response_char_uuid = BT_UUID_INIT_128(BT_UUID_RESPONSE_CHAR_VAL);

/* Pre-provisioned LE SC OOB data (R and C) */
static const struct bt_le_oob_sc_data static_oob_sc_data = {
	.r = { 0xa4, 0xaa, 0x7b, 0xba, 0x10, 0xdd, 0x3d, 0xa4,
	       0x10, 0x89, 0xb1, 0xfc, 0x17, 0xb6, 0xe8, 0xe5 },
	.c = { 0x24, 0x7e, 0xa7, 0xad, 0xb5, 0xc0, 0xfb, 0x67,
	       0xc9, 0xc1, 0xab, 0x7d, 0x98, 0x9c, 0x55, 0x61 },
};

struct session_state {
	bool oob_ok;
	bool token_ok;
	bool challenge_sent;
	bool trusted;
	uint8_t nonce[16];
	size_t nonce_len;
};

static struct session_state session;
static struct bt_conn *current_conn;

static uint8_t device_secret[32];
static mbedtls_pk_context backend_pk;
static bool backend_pk_ready;

static char last_oob_status[64];
static char last_token_status[96];
static char last_challenge[96];

static uint8_t oob_notify_enabled;
static uint8_t token_notify_enabled;
static uint8_t challenge_notify_enabled;
static const struct bt_gatt_attr *challenge_attr;

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_COMM_SVC_VAL),
};

static const struct bt_data sd[] = {
	BT_DATA(BT_DATA_NAME_COMPLETE, DEVICE_NAME, DEVICE_NAME_LEN),
};

static void reset_session(void)
{
	memset(&session, 0, sizeof(session));
	memset(last_oob_status, 0, sizeof(last_oob_status));
	memset(last_token_status, 0, sizeof(last_token_status));
	memset(last_challenge, 0, sizeof(last_challenge));
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
	size_t len = strlen(hex);

	if (len != out_len * 2) {
		return false;
	}

	for (size_t i = 0; i < out_len; i++) {
		char byte_str[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
		char *end = NULL;
		long v = strtol(byte_str, &end, 16);
		if (end == byte_str || v < 0 || v > 0xFF) {
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

	if (!pos) {
		return false;
	}

	pos = strchr(pos, ':');
	if (!pos) {
		return false;
	}

	pos = strchr(pos, '"');
	if (!pos) {
		return false;
	}
	pos++;

	const char *end = strchr(pos, '"');
	if (!end) {
		return false;
	}

	size_t len = end - pos;
	if (len + 1 > out_len) {
		return false;
	}

	memcpy(out, pos, len);
	out[len] = '\0';
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
	if (ret) {
		printk("Failed to decode backend public key (ret %d)\n", ret);
		return ret;
	}

	ret = mbedtls_pk_parse_public_key(&backend_pk, der_buf, der_len);
	if (ret) {
		printk("Failed to parse backend public key (ret %d)\n", ret);
		mbedtls_pk_free(&backend_pk);
		return -EINVAL;
	}

	backend_pk_ready = true;
	return 0;
}

static int verify_signature_es256(const uint8_t *payload, size_t payload_len,
				  const uint8_t *sig_der, size_t sig_len)
{
	if (!backend_pk_ready) {
		return -EFAULT;
	}

	uint8_t hash[32];
	int ret = mbedtls_sha256(payload, payload_len, hash, 0);
	if (ret) {
		return -EINVAL;
	}

	ret = mbedtls_pk_verify(&backend_pk, MBEDTLS_MD_SHA256, hash, sizeof(hash),
				sig_der, sig_len);
	if (ret) {
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

	if (!md_info || out_size < sizeof(mac)) {
		return -EINVAL;
	}

	int ret = mbedtls_md_hmac(md_info, key, key_len, msg, msg_len, mac);
	if (ret) {
		return -EINVAL;
	}

	memcpy(out_mac, mac, sizeof(mac));
	return 0;
}

static void notify_json(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			const char *json, uint8_t notify_flag)
{
	if (!conn || notify_flag != BT_GATT_CCC_NOTIFY) {
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
	if (ret) {
		return -EIO;
	}

	memcpy(session.nonce, nonce, sizeof(nonce));
	session.nonce_len = sizeof(nonce);
	session.challenge_sent = true;

	char nonce_hex[16 * 2 + 1];
	for (size_t i = 0; i < sizeof(nonce); i++) {
		snprintf(&nonce_hex[i * 2], 3, "%02x", nonce[i]);
	}

	snprintk(last_challenge, sizeof(last_challenge),
		 "{\"nonceHex\":\"%s\"}", nonce_hex);
	notify_json(conn, attr, last_challenge, challenge_notify_enabled);
	printk("Challenge sent: %s\n", last_challenge);
	return 0;
}

/* GATT characteristic callbacks */
static ssize_t oob_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			 const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
	ARG_UNUSED(attr);
	ARG_UNUSED(offset);
	ARG_UNUSED(flags);

	char json[128];

	if (len >= sizeof(json)) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}
	memcpy(json, buf, len);
	json[len] = '\0';

	char type[16];
	char oob_hex[80];

	if (!json_extract_string(json, "type", type, sizeof(type)) ||
	    strcmp(type, "OOB_INIT") != 0 ||
	    !json_extract_string(json, "oobKeyHex", oob_hex, sizeof(oob_hex))) {
		snprintk(last_oob_status, sizeof(last_oob_status),
			 "{\"type\":\"OOB_RESULT\",\"status\":\"ERROR\"}");
		notify_json(conn, attr, last_oob_status, oob_notify_enabled);
		return len;
	}

	if (strcmp(oob_hex, DEVICE_SECRET_HEX) != 0) {
		printk("OOB key mismatch\n");
		snprintk(last_oob_status, sizeof(last_oob_status),
			 "{\"type\":\"OOB_RESULT\",\"status\":\"ERROR\"}");
		notify_json(conn, attr, last_oob_status, oob_notify_enabled);
		return len;
	}

	session.oob_ok = true;
	snprintk(last_oob_status, sizeof(last_oob_status),
		 "{\"type\":\"OOB_RESULT\",\"status\":\"OK\"}");
	notify_json(conn, attr, last_oob_status, oob_notify_enabled);
	printk("OOB validated\n");
	return len;
}

static ssize_t token_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			   const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
	ARG_UNUSED(attr);
	ARG_UNUSED(offset);
	ARG_UNUSED(flags);

	char json[384];

	if (len >= sizeof(json)) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}
	memcpy(json, buf, len);
	json[len] = '\0';

	char payload_b64[256];
	char signature_b64[256];

	if (!json_extract_string(json, "payload", payload_b64, sizeof(payload_b64)) ||
	    !json_extract_string(json, "signature", signature_b64, sizeof(signature_b64))) {
		snprintk(last_token_status, sizeof(last_token_status),
			 "{\"type\":\"PAIR_TOKEN_RESULT\",\"status\":\"ERROR\"}");
		notify_json(conn, attr, last_token_status, token_notify_enabled);
		return len;
	}

	uint8_t payload_buf[256];
	uint8_t sig_buf[128];
	size_t payload_len = 0;
	size_t sig_len = 0;

	if (base64_decode_str(payload_b64, payload_buf, sizeof(payload_buf), &payload_len) ||
	    base64_decode_str(signature_b64, sig_buf, sizeof(sig_buf), &sig_len)) {
		snprintk(last_token_status, sizeof(last_token_status),
			 "{\"type\":\"PAIR_TOKEN_RESULT\",\"status\":\"ERROR\"}");
		notify_json(conn, attr, last_token_status, token_notify_enabled);
		return len;
	}

	char payload_json[256];
	if (payload_len >= sizeof(payload_json)) {
		snprintk(last_token_status, sizeof(last_token_status),
			 "{\"type\":\"PAIR_TOKEN_RESULT\",\"status\":\"ERROR\"}");
		notify_json(conn, attr, last_token_status, token_notify_enabled);
		return len;
	}
	memcpy(payload_json, payload_buf, payload_len);
	payload_json[payload_len] = '\0';

	char node_id[80];
	if (!json_extract_string(payload_json, "nodeId", node_id, sizeof(node_id)) ||
	    strcmp(node_id, NODE_ID_EXPECTED) != 0) {
		snprintk(last_token_status, sizeof(last_token_status),
			 "{\"type\":\"PAIR_TOKEN_RESULT\",\"status\":\"ERROR\"}");
		notify_json(conn, attr, last_token_status, token_notify_enabled);
		return len;
	}

	if (verify_signature_es256((uint8_t *)payload_buf, payload_len, sig_buf, sig_len)) {
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

	if (session.oob_ok && !session.challenge_sent && challenge_attr) {
		send_nonce(conn, challenge_attr);
	}

	return len;
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

	if (len >= sizeof(json)) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
	}
	memcpy(json, buf, len);
	json[len] = '\0';

	char mac_hex[80];
	if (!json_extract_string(json, "macHex", mac_hex, sizeof(mac_hex))) {
		return len;
	}

	uint8_t mac_bytes[32];
	if (!hex_to_bytes(mac_hex, mac_bytes, sizeof(mac_bytes))) {
		return len;
	}

	uint8_t expected_mac[32];
	if (!session.challenge_sent) {
		printk("MAC received before challenge\n");
		return len;
	}

	if (compute_hmac_sha256(device_secret, sizeof(device_secret),
				session.nonce, session.nonce_len,
				expected_mac, sizeof(expected_mac))) {
		return len;
	}

	if (memcmp(mac_bytes, expected_mac, sizeof(expected_mac)) == 0) {
		session.trusted = true;
		const char *ok = "{\"status\":\"AUTH_OK\"}";
		snprintk(last_challenge, sizeof(last_challenge), "%s", ok);
		if (challenge_attr) {
			notify_json(conn, challenge_attr, last_challenge, challenge_notify_enabled);
		}
		printk("Challenge response validated\n");
	} else {
		const char *err = "{\"status\":\"ERROR\"}";
		snprintk(last_challenge, sizeof(last_challenge), "%s", err);
		if (challenge_attr) {
			notify_json(conn, challenge_attr, last_challenge, challenge_notify_enabled);
		}
		printk("Challenge response failed\n");
	}

	return len;
}

/* CCC handlers */
static void oob_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
	ARG_UNUSED(attr);
	oob_notify_enabled = (value == BT_GATT_CCC_NOTIFY) ? BT_GATT_CCC_NOTIFY : 0;
}

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
	BT_GATT_CHARACTERISTIC(&oob_char_uuid.uuid,
			       BT_GATT_CHRC_WRITE | BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_WRITE_ENCRYPT,
			       NULL, oob_write, NULL),
	BT_GATT_CCC(oob_ccc_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),

	BT_GATT_CHARACTERISTIC(&token_char_uuid.uuid,
			       BT_GATT_CHRC_WRITE | BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_WRITE_ENCRYPT,
			       NULL, token_write, NULL),
	BT_GATT_CCC(token_ccc_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),

	BT_GATT_CHARACTERISTIC(&challenge_char_uuid.uuid,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_READ_ENCRYPT,
			       challenge_read, NULL, NULL),
	BT_GATT_CCC(challenge_ccc_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),

			       BT_GATT_CHARACTERISTIC(&response_char_uuid.uuid,
			       BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_WRITE_ENCRYPT,
			       NULL, response_write, NULL),
);

static void init_attr_refs(void)
{
	/* Challenge characteristic value attribute index within the service */
	challenge_attr = &comm_svc.attrs[8];
}

/* Connection callbacks */
static void connected(struct bt_conn *conn, uint8_t err)
{
	if (err) {
		printk("Connection failed (err %u)\n", err);
		return;
	}

	current_conn = bt_conn_ref(conn);
	reset_session();

	printk("Connected, requesting security level 4 (LESC + MITM via OOB)\n");

	err = bt_conn_set_security(conn, BT_SECURITY_L4);
	if (err) {
		printk("bt_conn_set_security failed (err %d)\n", err);
	}
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	printk("Disconnected (reason %u)\n", reason);
	if (current_conn) {
		bt_conn_unref(current_conn);
		current_conn = NULL;
	}
	reset_session();
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected    = connected,
	.disconnected = disconnected,
};

/* Authentication callbacks: OOB data + status logging */
static void auth_oob_data_request(struct bt_conn *conn, struct bt_conn_oob_info *info)
{
	int err;

	if (info->type != BT_CONN_OOB_LE_SC) {
		printk("OOB: unsupported type %u\n", info->type);
		bt_conn_auth_cancel(conn);
		return;
	}

	const struct bt_le_oob_sc_data *local = NULL;
	const struct bt_le_oob_sc_data *remote = NULL;

	switch (info->lesc.oob_config) {
	case BT_CONN_OOB_LOCAL_ONLY:
		local = &static_oob_sc_data;
		break;
	case BT_CONN_OOB_REMOTE_ONLY:
		remote = &static_oob_sc_data;
		break;
	case BT_CONN_OOB_BOTH_PEERS:
		local = &static_oob_sc_data;
		remote = &static_oob_sc_data;
		break;
	case BT_CONN_OOB_NO_DATA:
	default:
		printk("OOB: no data requested (config %u)\n", info->lesc.oob_config);
		bt_conn_auth_cancel(conn);
		return;
	}

	err = bt_le_oob_set_sc_data(conn, local, remote);
	if (err) {
		printk("Failed to set SC OOB data: %d\n", err);
		bt_conn_auth_cancel(conn);
		return;
	}

	printk("Provided LE SC OOB data (config %u)\n", info->lesc.oob_config);
}

static void auth_cancel(struct bt_conn *conn)
{
	printk("Auth request cancelled\n");
}

static const struct bt_conn_auth_cb auth_cb = {
	.oob_data_request = auth_oob_data_request,
	.cancel = auth_cancel,
};

static void pairing_complete(struct bt_conn *conn, bool bonded)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	printk("Pairing completed with %s (bonded=%d)\n", addr, bonded);
}

static void pairing_failed(struct bt_conn *conn, enum bt_security_err reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	printk("Pairing failed with %s (reason=%d)\n", addr, reason);
}

static struct bt_conn_auth_info_cb auth_info_cb = {
	.pairing_complete = pairing_complete,
	.pairing_failed = pairing_failed,
};

static int init_crypto_material(void)
{
	if (!hex_to_bytes(DEVICE_SECRET_HEX, device_secret, sizeof(device_secret))) {
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
	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
		return 0;
	}

	printk("Bluetooth initialized\n");

	if (IS_ENABLED(CONFIG_SETTINGS)) {
		settings_load();
		printk("Settings loaded\n");
	}

	err = init_crypto_material();
	if (err) {
		printk("Crypto init failed (err %d)\n", err);
		return 0;
	}

	init_attr_refs();

	err = bt_conn_auth_cb_register(&auth_cb);
	if (err) {
		printk("Failed to register auth callbacks: %d\n", err);
		return 0;
	}

	err = bt_conn_auth_info_cb_register(&auth_info_cb);
	if (err) {
		printk("Failed to register auth info callbacks: %d\n", err);
		return 0;
	}

	err = bt_le_adv_start(BT_LE_ADV_CONN, ad, ARRAY_SIZE(ad), sd, ARRAY_SIZE(sd));
	if (err) {
		printk("Advertising failed to start (err %d)\n", err);
		return 0;
	}

	printk("Advertising started\n");

	for (;;) {
		k_sleep(K_SECONDS(1));
	}

	return 0;
}
