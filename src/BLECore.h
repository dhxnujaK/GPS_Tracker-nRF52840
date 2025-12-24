#pragma once

#include <zephyr/bluetooth/conn.h>
#include <stdbool.h>
#include <stddef.h>

struct session_state
{
	bool token_ok;
	bool challenge_sent;
	bool trusted;
	bool bonded;
	uint8_t nonce[16];
	size_t nonce_len;
};

extern struct session_state session;
extern struct bt_conn *current_conn;
extern struct bt_conn *keyfob_conn;

int ble_clear_bonds(void);
int ble_core_init(void);
int ble_core_start(const struct bt_data *ad, size_t ad_len,
				   const struct bt_data *sd, size_t sd_len,
				   bool load_settings);
int ble_link_keyfob_start(const char *keyfob_id);
void ble_keyfob_bond_phase_start(void);
