/*
 * Immobilizer commissioning and authentication firmware
 */

#include <zephyr/types.h>
#include <zephyr/sys/printk.h>
#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/settings/settings.h>

#include "app_config.h"
#include "authorizationtoken.h"
#include "challengeresponse.h"
#include "BLECore.h"

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
											  NULL, response_write, NULL));

static void init_attr_refs(void)
{
	/* Challenge characteristic value attribute index within the service */
	challenge_set_attr(&comm_svc.attrs[5]);
}

static int init_crypto_material(void)
{
	if (challenge_load_device_secret())
	{
		return -EINVAL;
	}

	return auth_init_backend_public_key();
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
	(void)ble_clear_bonds();

	err = init_crypto_material();
	if (err)
	{
		printk("Crypto init failed (err %d)\n", err);
		return 0;
	}

	init_attr_refs();

	err = ble_core_init();
	if (err)
	{
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
