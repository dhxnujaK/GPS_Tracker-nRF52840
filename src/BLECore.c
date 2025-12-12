#include "BLECore.h"
#include "authorizationtoken.h"
#include "challengeresponse.h"

#include <string.h>
#include <zephyr/sys/printk.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/settings/settings.h>

struct session_state session;
struct bt_conn *current_conn;

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

	current_conn = bt_conn_ref(conn);
	reset_session();

	/* Enable notifications by default so status/nonce messages are sent even if CCC isn't set. */
	token_force_notify_enable();
	challenge_force_notify_enable();

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

	err = bt_le_adv_start(BT_LE_ADV_CONN, ad, ad_len, sd, sd_len);
	if (err)
	{
		printk("Advertising failed to start (err %d)\n", err);
		return err;
	}

	printk("Advertising started\n");
	return 0;
}
