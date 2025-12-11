#pragma once

#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <stdbool.h>
#include <stddef.h>

bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_len);
int base64_decode_str(const char *b64, uint8_t *out, size_t out_size, size_t *out_len);
bool json_extract_string(const char *json, const char *key, char *out, size_t out_len);
bool json_extract_uint(const char *json, const char *key, uint32_t *out);
void notify_json(struct bt_conn *conn, const struct bt_gatt_attr *attr,
				 const char *json, uint8_t notify_flag);
