/*
 * MeshSentry wire format.
 *
 * Every frame is an ESP-NOW broadcast so that all neighbours can overhear it
 * (required by the watchdog). The intended next hop is carried in the header.
 *
 *   +--------+------+-------+------+------+-----+-----+-----+-----+---------+------+
 *   | magic  | type |  tx   | txseq| orig | seq | next| hop | len | payload | tag  |
 *   |   1    |  1   |   2   |  4   |  2   |  2  |  2  |  1  |  1  |  len    |  8   |
 *   +--------+------+-------+------+------+-----+-----+-----+-----+---------+------+
 *
 * tag = HMAC-SHA256(K_net, header || payload) truncated to 64 bits.
 * txseq is a per-transmitter counter that changes on every transmission and
 * is checked against a 64-entry sliding window (anti-replay).
 */
#pragma once

#include <stdint.h>

#define MS_MAGIC          0xA5
#define MS_TAG_LEN        8
#define MS_SINK_ID        0x0000
#define MS_BCAST_ID       0xFFFF
#define MS_MAX_FRAME      250          /* ESP_NOW_MAX_DATA_LEN (v1) */
#define MS_MAX_HOPS       15
#define MS_COST_INF       0xFFFF

typedef enum {
    MS_T_BEACON = 1,
    MS_T_DATA   = 2,
    MS_T_REPORT = 3,
    MS_T_CTL    = 4,   /* sink-signed control flood (ASNL + blacklist) */
    MS_T_JUNK   = 5,   /* testbed flooding traffic */
} ms_type_t;

typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  type;
    uint16_t tx;
    uint32_t txseq;
    uint16_t orig;
    uint16_t seq;
    uint16_t next;
    uint8_t  hop;
    uint8_t  len;
} ms_hdr_t;

_Static_assert(sizeof(ms_hdr_t) == 16, "header must be 16 bytes");

#define MS_OVERHEAD       (sizeof(ms_hdr_t) + MS_TAG_LEN)   /* 24 bytes */
#define MS_MAX_PAYLOAD    (MS_MAX_FRAME - MS_OVERHEAD)

typedef struct __attribute__((packed)) {
    uint16_t cost_q8;      /* path ETX * 256, MS_COST_INF = no route */
    uint16_t parent;
    uint32_t uptime_s;
} ms_beacon_t;

typedef struct __attribute__((packed)) {
    uint32_t t_ms;         /* generation time at the originator */
    int16_t  temp_c10;     /* example sensor payload */
    uint16_t vbat_mv;
    uint8_t  pad[8];
} ms_data_t;

/* One per-neighbour feature record in a report (10 bytes). */
#define MS_REC_FLOOD      0x01  /* local flooding verdict */
#define MS_REC_RATE_WARM  0x02  /* rate baseline is established */
#define MS_REC_ASNL       0x04  /* monitor holds a signed sink list */
#define MS_REC_BEACON     0x08  /* beacons heard in this window */
#define MS_REC_REPLAY_SH  4     /* bits 4-5: replay count (saturating 3) */
#define MS_REC_CLAIM_SH   6     /* bits 6-7: bad hop-1 claims (sat. 3) */

typedef struct __attribute__((packed)) {
    uint16_t nbr;
    uint8_t  handed;      /* forwards expected (3-window sliding sum) */
    uint8_t  overheard;   /* forwards overheard */
    uint8_t  prr_q8;      /* EWMA beacon reception ratio * 255 */
    int8_t   rssi;        /* mean RSSI of fresh frames (dBm) */
    uint8_t  rssi_n;
    uint8_t  rate;        /* frames/s in the window (saturating) */
    uint8_t  flags;
    uint8_t  reserved;
} ms_rec_t;

_Static_assert(sizeof(ms_rec_t) == 10, "record must be 10 bytes");

#define MS_MAX_RECS       16

typedef struct __attribute__((packed)) {
    uint16_t window;
    uint8_t  n_rec;
    uint8_t  reserved;
    ms_rec_t rec[];
} ms_report_t;

#define MS_SIG_LEN        64   /* ECDSA-P256 raw r||s */

typedef struct __attribute__((packed)) {
    uint32_t ctl_seq;
    uint32_t sink_ms;      /* sink clock: aligns detection windows */
    uint8_t  n_asnl;
    uint8_t  n_bl;
    uint16_t ids[];        /* n_asnl sink neighbours, then n_bl blacklisted */
    /* followed by MS_SIG_LEN signature over ctl_seq..ids */
} ms_ctl_t;
