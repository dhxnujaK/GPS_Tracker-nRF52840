#include "BLECore.h"
#include "authorizationtoken.h"
#include "challengeresponse.h"

#include <errno.h>
#include <string.h>
#include <zephyr/sys/printk.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>

struct session_state session;
struct bt_conn *current_conn;
struct bt_conn *keyfob_conn;

static char keyfob_target_id[80];
static uint16_t keyfob_challenge_handle;
static uint16_t keyfob_response_handle;
static uint16_t keyfob_response_ccc_handle;
static uint16_t keyfob_svc_start;
static uint16_t keyfob_svc_end;
static struct bt_gatt_discover_params discover_params;
static struct bt_gatt_subscribe_params subscribe_params;

#define BT_UUID_COMM_SVC_VAL \
	BT_UUID_128_ENCODE(0x23d7f4a1, 0x8c5e, 0x4af2, 0x91b7, 0x77c3f5a0c101)
#define BT_UUID_CHALLENGE_CHAR_VAL \
	BT_UUID_128_ENCODE(0x23d7f4a4, 0x8c5e, 0x4af2, 0x91b7, 0x77c3f5a0c101)
#define BT_UUID_RESPONSE_CHAR_VAL \
	BT_UUID_128_ENCODE(0x23d7f4a5, 0x8c5e, 0x4af2, 0x91b7, 0x77c3f5a0c101)

static struct bt_uuid_128 keyfob_comm_uuid = BT_UUID_INIT_128(BT_UUID_COMM_SVC_VAL);
static struct bt_uuid_128 keyfob_challenge_uuid = BT_UUID_INIT_128(BT_UUID_CHALLENGE_CHAR_VAL);
static struct bt_uuid_128 keyfob_response_uuid = BT_UUID_INIT_128(BT_UUID_RESPONSE_CHAR_VAL);

static const struct bt_data *adv_ad;
static const struct bt_data *adv_sd;
static size_t adv_ad_len;
static size_t adv_sd_len;
static bool adv_running;
static bool adv_paused_for_scan;
static bool keyfob_scan_pending;
static bool keyfob_scanning;
static struct k_work_delayable secure_ready_work;

static void secure_ready_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	if (current_conn)
	{
		token_notify_secure_ready(current_conn);
	}
}

static int adv_start(void)
{
	if (!adv_ad || !adv_sd)
	{
		return -EINVAL;
	}

	int err = bt_le_adv_start(BT_LE_ADV_CONN, adv_ad, adv_ad_len, adv_sd, adv_sd_len);
	if (!err)
	{
		adv_running = true;
	}
	return err;
}

static void adv_stop(void)
{
	if (!adv_running)
	{
		return;
	}

	if (bt_le_adv_stop() == 0)
	{
		adv_running = false;
	}
}

static void keyfob_reset_discovery(void)
{
	keyfob_challenge_handle = 0;
	keyfob_response_handle = 0;
	keyfob_response_ccc_handle = 0;
	keyfob_svc_start = 0;
	keyfob_svc_end = 0;
	memset(&discover_params, 0, sizeof(discover_params));
	memset(&subscribe_params, 0, sizeof(subscribe_params));
}

static uint8_t keyfob_notify_cb(struct bt_conn *conn,
								struct bt_gatt_subscribe_params *params,
								const void *data, uint16_t length)
{
	ARG_UNUSED(conn);

	if (!data || length == 0)
	{
		return BT_GATT_ITER_CONTINUE;
	}

	printk("Keyfob response notify received (%u bytes)\n", length);
	(void)challenge_process_response_json(current_conn, data, length);
	return BT_GATT_ITER_CONTINUE;
}

static void keyfob_send_nonce(void)
{
	if (!keyfob_conn || keyfob_challenge_handle == 0)
	{
		return;
	}

	if (challenge_send_nonce(current_conn))
	{
		return;
	}

	const char *json = NULL;
	size_t json_len = 0;
	challenge_get_last_json(&json, &json_len);
	if (!json || json_len == 0)
	{
		return;
	}

	(void)bt_gatt_write_without_response(keyfob_conn, keyfob_challenge_handle,
										 json, json_len, false);
	printk("Keyfob nonce sent\n");
}

static uint8_t keyfob_discover_cb(struct bt_conn *conn,
								  const struct bt_gatt_attr *attr,
								  struct bt_gatt_discover_params *params)
{
	if (!attr)
	{
		if (params->type == BT_GATT_DISCOVER_CHARACTERISTIC &&
			keyfob_response_handle && keyfob_svc_end)
		{
			discover_params.uuid = BT_UUID_GATT_CCC;
			discover_params.start_handle = keyfob_response_handle + 1;
			discover_params.end_handle = keyfob_svc_end;
			discover_params.type = BT_GATT_DISCOVER_DESCRIPTOR;
			bt_gatt_discover(conn, &discover_params);
		}
		return BT_GATT_ITER_STOP;
	}

	if (params->type == BT_GATT_DISCOVER_PRIMARY)
	{
		const struct bt_gatt_service_val *svc = attr->user_data;
		keyfob_svc_start = attr->handle + 1;
		keyfob_svc_end = svc->end_handle;

		discover_params.uuid = NULL;
		discover_params.start_handle = keyfob_svc_start;
		discover_params.end_handle = keyfob_svc_end;
		discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
		bt_gatt_discover(conn, &discover_params);
		return BT_GATT_ITER_STOP;
	}

	if (params->type == BT_GATT_DISCOVER_CHARACTERISTIC)
	{
		const struct bt_gatt_chrc *chrc = attr->user_data;
		if (!bt_uuid_cmp(chrc->uuid, &keyfob_challenge_uuid.uuid))
		{
			keyfob_challenge_handle = chrc->value_handle;
		}
		if (!bt_uuid_cmp(chrc->uuid, &keyfob_response_uuid.uuid))
		{
			keyfob_response_handle = chrc->value_handle;
		}
		return BT_GATT_ITER_CONTINUE;
	}

	if (params->type == BT_GATT_DISCOVER_DESCRIPTOR)
	{
		keyfob_response_ccc_handle = attr->handle;
		subscribe_params.notify = keyfob_notify_cb;
		subscribe_params.value = BT_GATT_CCC_NOTIFY;
		subscribe_params.value_handle = keyfob_response_handle;
		subscribe_params.ccc_handle = keyfob_response_ccc_handle;
		bt_gatt_subscribe(conn, &subscribe_params);
		printk("Keyfob response subscribed\n");
		keyfob_send_nonce();
		return BT_GATT_ITER_STOP;
	}

	return BT_GATT_ITER_STOP;
}

static void keyfob_start_discovery(struct bt_conn *conn)
{
	keyfob_reset_discovery();
	printk("Keyfob discovery started\n");
	discover_params.uuid = &keyfob_comm_uuid.uuid;
	discover_params.start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
	discover_params.end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
	discover_params.type = BT_GATT_DISCOVER_PRIMARY;
	discover_params.func = keyfob_discover_cb;
	bt_gatt_discover(conn, &discover_params);
}

static bool parse_uuid_ad(struct bt_data *data, void *user_data)
{
	bool *match = user_data;
	struct bt_uuid_128 uuid;

	if (data->type != BT_DATA_UUID128_ALL &&
		data->type != BT_DATA_UUID128_SOME)
	{
		return true;
	}

	for (size_t i = 0; i + 16 <= data->data_len; i += 16)
	{
		memcpy(&uuid.val, &data->data[i], 16);
		uuid.uuid.type = BT_UUID_TYPE_128;
		if (!bt_uuid_cmp(&uuid.uuid, &keyfob_comm_uuid.uuid))
		{
			*match = true;
			return false;
		}
	}

	return true;
}

static bool parse_name_ad(struct bt_data *data, void *user_data)
{
	bool *match = user_data;

	if (data->type != BT_DATA_NAME_COMPLETE &&
		data->type != BT_DATA_NAME_SHORTENED)
	{
		return true;
	}
	if (data->data_len == 0)
	{
		return true;
	}

	char name[32];
	size_t copy_len = MIN(data->data_len, sizeof(name) - 1);
	memcpy(name, data->data, copy_len);
	name[copy_len] = '\0';
	if (strstr(name, "Keyfob") ||
		(keyfob_target_id[0] && strstr(name, keyfob_target_id)))
	{
		*match = true;
		return false;
	}

	return true;
}

static bool ad_has_uuid(struct net_buf_simple *ad)
{
	bool found = false;

	bt_data_parse(ad, parse_uuid_ad, &found);
	return found;
}

static void scan_recv_legacy(const bt_addr_le_t *addr, int8_t rssi,
							 uint8_t type, struct net_buf_simple *ad)
{
	bool name_match = false;

	ARG_UNUSED(rssi);
	ARG_UNUSED(type);

	if (keyfob_conn)
	{
		return;
	}

	if (!ad_has_uuid(ad))
	{
		return;
	}

	bt_data_parse(ad, parse_name_ad, &name_match);

	if (!name_match && keyfob_target_id[0])
	{
		/* If name isn't present, allow UUID-only match. */
	}

	bt_le_scan_stop();
	keyfob_scanning = false;
	printk("Keyfob advertisement matched, connecting\n");
	bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN,
					  BT_LE_CONN_PARAM_DEFAULT, &keyfob_conn);
}

static void reset_session(void)
{
	memset(&session, 0, sizeof(session));
	token_reset();
	challenge_reset();
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	if (err)
	{
		printk("Connection failed (err %u)\n", err);
		return;
	}

	struct bt_conn_info info;
	if (bt_conn_get_info(conn, &info) == 0 &&
		info.role == BT_CONN_ROLE_CENTRAL)
	{
		printk("Keyfob connected\n");
		keyfob_conn = bt_conn_ref(conn);
		if (bt_conn_set_security(conn, BT_SECURITY_L2))
		{
			printk("Keyfob security request failed\n");
		}
		keyfob_start_discovery(conn);
		return;
	}

	current_conn = bt_conn_ref(conn);
	reset_session();

	/* Wait for CCC subscription before notifying. */

	printk("Connected, requesting security level 2 (LESC)\n");

	err = bt_conn_set_security(conn, BT_SECURITY_L2);
	if (err)
	{
		printk("bt_conn_set_security failed (err %d)\n", err);
	}
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	printk("Disconnected (reason %u)\n", reason);
	struct bt_conn_info info;
	if (bt_conn_get_info(conn, &info) == 0 &&
		info.role == BT_CONN_ROLE_CENTRAL)
	{
		if (keyfob_conn)
		{
			bt_conn_unref(keyfob_conn);
			keyfob_conn = NULL;
		}
		keyfob_reset_discovery();
		keyfob_scanning = false;
		if (adv_paused_for_scan)
		{
			adv_paused_for_scan = false;
			if (adv_start() == 0)
			{
				printk("Advertising restarted\n");
			}
		}
		return;
	}
	if (current_conn)
	{
		bt_conn_unref(current_conn);
		current_conn = NULL;
	}
	reset_session();
	if (keyfob_scan_pending)
	{
		keyfob_scan_pending = false;
		(void)ble_link_keyfob_start(keyfob_target_id);
	}
}

static void security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
	if (err)
	{
		printk("Security change failed with %s level %u (err %d)\n", addr, level, err);
	}
	else
	{
		printk("Security changed with %s level %u\n", addr, level);
		if (level >= BT_SECURITY_L2)
		{
			struct bt_conn_info info;
			if (bt_conn_get_info(conn, &info) == 0)
			{
				if (info.role == BT_CONN_ROLE_PERIPHERAL)
				{
					(void)k_work_schedule(&secure_ready_work, K_MSEC(200));
				}
				else
				{
					printk("Keyfob security level %u\n", level);
				}
			}
		}
	}
}

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
	printk("Pairing failed with %s (reason=%d)\n", addr, reason);
}

static struct bt_conn_auth_info_cb auth_info_cb = {
	.pairing_complete = pairing_complete,
	.pairing_failed = pairing_failed,
};

int ble_clear_bonds(void)
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
	return err;
}

int ble_core_init(void)
{
	int err = bt_conn_auth_cb_register(&auth_cb);
	if (err)
	{
		printk("Failed to register auth callbacks: %d\n", err);
		return err;
	}

	err = bt_conn_auth_info_cb_register(&auth_info_cb);
	if (err)
	{
		printk("Failed to register auth info callbacks: %d\n", err);
		return err;
	}

	return 0;
}

int ble_core_start(const struct bt_data *ad, size_t ad_len,
				   const struct bt_data *sd, size_t sd_len,
				   bool load_settings)
{
	int err;

	err = bt_enable(NULL);
	if (err)
	{
		printk("Bluetooth init failed (err %d)\n", err);
		return err;
	}

	printk("Bluetooth initialized\n");
	adv_ad = ad;
	adv_sd = sd;
	adv_ad_len = ad_len;
	adv_sd_len = sd_len;
	k_work_init_delayable(&secure_ready_work, secure_ready_work_handler);

	if (load_settings && IS_ENABLED(CONFIG_SETTINGS))
	{
		settings_load();
		printk("Settings loaded\n");
	}

	/* Clear existing bonds to avoid stale keys during development */
	(void)ble_clear_bonds();

	err = ble_core_init();
	if (err)
	{
		printk("BLE core init failed (err %d)\n", err);
		return err;
	}

	err = adv_start();
	if (err)
	{
		printk("Advertising failed to start (err %d)\n", err);
		return err;
	}

	printk("Advertising started\n");
	return 0;
}

int ble_link_keyfob_start(const char *keyfob_id)
{
	if (!keyfob_id || !keyfob_id[0])
	{
		return -EINVAL;
	}

	strncpy(keyfob_target_id, keyfob_id, sizeof(keyfob_target_id));
	keyfob_target_id[sizeof(keyfob_target_id) - 1] = '\0';

	printk("Keyfob scan requested (connected=%s scanning=%s)\n",
		   current_conn ? "yes" : "no",
		   keyfob_scanning ? "yes" : "no");
	printk("Keyfob target id: %s\n", keyfob_target_id);

	if (keyfob_conn)
	{
		return -EALREADY;
	}

	if (keyfob_scanning)
	{
		return -EALREADY;
	}

	if (current_conn)
	{
		keyfob_scan_pending = true;
		return 0;
	}

	(void)bt_le_scan_stop();
	adv_stop();
	adv_paused_for_scan = true;

	struct bt_le_scan_param scan_param = {
		.type = BT_HCI_LE_SCAN_ACTIVE,
		.options = BT_LE_SCAN_OPT_NONE,
		.interval = 0x0010,
		.window = 0x0010,
	};

	int err = bt_le_scan_start(&scan_param, scan_recv_legacy);
	if (err)
	{
		printk("Keyfob scan start failed (err %d)\n", err);
		adv_paused_for_scan = false;
		(void)adv_start();
		keyfob_scanning = false;
	}
	else
	{
		keyfob_scanning = true;
		printk("Keyfob scan started\n");
	}
	return err;
}
