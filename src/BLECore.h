#pragma once

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

int ble_clear_bonds(void);
int ble_core_init(void);
