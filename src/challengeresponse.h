#pragma once

#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>

int challenge_load_device_secret(void);
int challenge_send_nonce(struct bt_conn *conn);
ssize_t challenge_read(struct bt_conn *conn, const struct bt_gatt_attr *attr,
					   void *buf, uint16_t len, uint16_t offset);
ssize_t response_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
					   const void *buf, uint16_t len, uint16_t offset, uint8_t flags);
void challenge_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value);
void challenge_force_notify_enable(void);
void challenge_set_attr(const struct bt_gatt_attr *attr);
void challenge_reset(void);
