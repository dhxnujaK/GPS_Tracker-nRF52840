#pragma once

#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>

int auth_init_backend_public_key(void);
ssize_t token_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
					const void *buf, uint16_t len, uint16_t offset, uint8_t flags);
void token_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value);
void token_force_notify_enable(void);
void token_reset(void);
