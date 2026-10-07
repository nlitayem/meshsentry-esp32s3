/*
 * ESP-NOW broadcast mesh with ETX gradient routing towards a sink.
 * Hosts the MeshSentry monitor (all nodes) and fusion (sink).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "ms_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Optional behaviour hooks, used only by the testbed attack emulation. */
typedef struct {
    /* return true to silently drop a frame this node should forward */
    bool (*drop_forward)(const ms_hdr_t *h);
    /* rewrite the advertised route before a beacon is sent */
    void (*beacon_override)(uint8_t *hop, uint16_t *cost_q8, uint16_t *parent);
    /* raw copy of every received frame (before authentication) */
    void (*on_raw_rx)(const uint8_t *frame, int len);
} mesh_hooks_t;

typedef struct {
    uint16_t node_id;     /* MS_SINK_ID for the sink */
    bool     passive;     /* receive only: no beacons, data or reports */
} mesh_config_t;

esp_err_t mesh_start(const mesh_config_t *cfg, const mesh_hooks_t *hooks);

/* Authenticated frame from this radio. tx_id normally equals the node id;
 * the Sybil emulation passes fabricated identities. Thread-safe. */
esp_err_t mesh_send_frame(ms_type_t type, uint16_t tx_id, uint16_t orig,
                          uint16_t seq, uint16_t next, uint8_t hop,
                          const void *payload, uint8_t len);

/* Transmit bytes verbatim (replay emulation). Thread-safe. */
esp_err_t mesh_send_raw(const uint8_t *frame, int len);

uint32_t mesh_now_ms(void);
uint16_t mesh_self_id(void);
void     mesh_get_route(uint8_t *hop, uint16_t *cost_q8, uint16_t *parent);

/* ---- authentication (mesh_auth.c) --------------------------------------- */
esp_err_t mesh_auth_init(void);
/* tag = HMAC-SHA256(K_net, msg)[0..7] */
esp_err_t mesh_auth_tag(const uint8_t *msg, size_t len, uint8_t tag[MS_TAG_LEN]);
bool      mesh_auth_verify(const uint8_t *msg, size_t len, const uint8_t tag[MS_TAG_LEN]);
/* ECDSA-P256/SHA-256 over control payloads (sign: sink only) */
esp_err_t mesh_ctl_sign(const uint8_t *msg, size_t len, uint8_t sig[MS_SIG_LEN]);
bool      mesh_ctl_verify(const uint8_t *msg, size_t len, const uint8_t sig[MS_SIG_LEN]);

#ifdef __cplusplus
}
#endif
