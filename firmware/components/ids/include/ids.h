/*
 * MeshSentry intrusion detection.
 *
 * ids_monitor.c  per-neighbour feature extraction on every node (watchdog,
 *                anti-replay window, rate baseline, route-claim check) and
 *                the neighbour table shared with routing.
 * ids_detect.c   local detectors applied to one feature record; used both by
 *                monitors (local reaction) and by the sink (fusion).
 * ids_fusion.c   sink-only trust-weighted consensus and RSSI-signature Sybil
 *                detection.
 *
 * The Python reference implementation in sim/meshsentry/ids.py mirrors this
 * code and is used for the simulation study.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "ms_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IDS_MAX_NBRS      24
#define IDS_MAX_PENDING   48

typedef enum {
    IDS_A_FWD    = 1 << 0,   /* selective forwarding / blackhole */
    IDS_A_FLOOD  = 1 << 1,   /* frame-rate anomaly */
    IDS_A_ROUTE  = 1 << 2,   /* forged hop-1 claim (sinkhole) */
    IDS_A_REPLAY = 1 << 3,   /* stale authenticated frames */
    IDS_A_SYBIL  = 1 << 4,   /* shared RSSI signature */
} ids_alert_t;

#define IDS_BLACKLIST_MASK (IDS_A_FWD | IDS_A_FLOOD | IDS_A_ROUTE | IDS_A_SYBIL)

typedef struct {
    uint16_t id;
    uint16_t cost_q8;
    uint16_t parent;
    uint8_t  hop;
    uint8_t  prr_q8;
    bool     prr_valid;
    uint8_t  beacons;        /* beacons heard in the current window */
    int8_t   rssi;
    uint32_t last_ms;
    bool     local_suspect;
} ids_nbr_info_t;

/* ---- monitor (all nodes) ------------------------------------------------ */
void ids_init(uint16_t self_id);

/* Feed every authenticated frame. Returns false if the frame is a replay
 * (stale per-hop sequence number) and must be discarded. */
bool ids_on_frame(const ms_hdr_t *h, const void *payload, int8_t rssi,
                  uint32_t now_ms);

/* Register a watchdog expectation that `next` forwards (type, orig, seq). */
void ids_expect(uint16_t next, uint8_t type, uint16_t orig, uint16_t seq,
                bool own, uint32_t now_ms);

/* Install the signed sink-neighbour list carried by a verified CTL frame. */
void ids_set_asnl(const uint16_t *ids, int n);

/* Close a detection window: fills up to `max` records (alerts first) and
 * returns how many were written. */
int ids_end_window(uint16_t window, ms_rec_t *out, int max, uint32_t now_ms);

int ids_neighbours(ids_nbr_info_t *out, int max);

/* ---- detectors ---------------------------------------------------------- */
double  ids_binom_cdf(int k, int n, double q);
uint8_t ids_eligible(const ms_rec_t *r);
uint8_t ids_local_verdicts(const ms_rec_t *r);
const char *ids_alert_name(ids_alert_t a);

/* ---- fusion (sink) ------------------------------------------------------ */
typedef void (*ids_decision_cb_t)(uint16_t id, ids_alert_t type,
                                  uint16_t window);

void ids_fusion_init(void);
void ids_fusion_add_report(uint16_t mon, uint16_t window,
                           const ms_rec_t *rec, int n);
int  ids_fusion_decide(uint16_t window, ids_decision_cb_t cb);
int  ids_fusion_blacklist(uint16_t *out, int max);
float ids_fusion_trust(uint16_t mon);

#ifdef __cplusplus
}
#endif
