/*
 * Per-neighbour monitoring on every node. Mirrors Node.on_rx(), Node.expect()
 * and Node.end_window() in sim/meshsentry/sim.py.
 *
 * Called only from the mesh task, so no locking is needed.
 */
#include <string.h>
#include <math.h>
#include "sdkconfig.h"
#include "ids.h"

#define W_S            CONFIG_MS_WINDOW_S
#define EXP_BEACONS    ((float)W_S * 1000.0f / CONFIG_MS_BEACON_MS)
#define RATE_K         (CONFIG_MS_RATE_K_X10 / 10.0f)
#define PENDING_MS     400
#define N_SLIDE        3              /* watchdog evidence spans 3 windows */
#define ASNL_MAX       64

typedef struct {
    bool     used;
    uint16_t id;
    uint32_t last_ms;
    /* current-window counters */
    uint16_t frames;
    uint16_t beacons;
    uint16_t rssi_n;
    uint16_t replays;
    int32_t  rssi_sum;
    uint8_t  bad_claims;
    /* watchdog, sliding over N_SLIDE windows */
    uint8_t  hand[N_SLIDE];
    uint8_t  over[N_SLIDE];
    /* link and rate statistics */
    float    prr;
    bool     prr_valid;
    float    mu, dev;
    uint16_t warm;
    /* routing information from beacons */
    uint16_t cost_q8;
    uint16_t parent;
    uint8_t  hop;
    /* anti-replay window (RFC 4303 style) */
    bool     seq_valid;
    uint32_t max_seq;
    uint64_t bitmap;
    bool     local_suspect;
} nbr_t;

typedef struct {
    bool     used;
    bool     own;
    uint8_t  type;
    uint16_t nbr;
    uint16_t orig;
    uint16_t seq;
    uint32_t deadline_ms;
} pending_t;

static uint16_t  s_self;
static nbr_t     s_nbr[IDS_MAX_NBRS];
static pending_t s_pend[IDS_MAX_PENDING];
static int       s_pend_next;
static uint8_t   s_cur;               /* index into hand[]/over[] */
static uint16_t  s_asnl[2][ASNL_MAX]; /* last two signed sink lists */
static uint8_t   s_asnl_n[2];
static bool      s_asnl_known;

void ids_init(uint16_t self_id)
{
    s_self = self_id;
    memset(s_nbr, 0, sizeof(s_nbr));
    memset(s_pend, 0, sizeof(s_pend));
    s_pend_next = 0;
    s_cur = 0;
    s_asnl_known = false;
    s_asnl_n[0] = s_asnl_n[1] = 0;
}

static nbr_t *nbr_find(uint16_t id)
{
    for (int i = 0; i < IDS_MAX_NBRS; i++) {
        if (s_nbr[i].used && s_nbr[i].id == id) {
            return &s_nbr[i];
        }
    }
    return NULL;
}

static nbr_t *nbr_get(uint16_t id, uint32_t now_ms)
{
    nbr_t *n = nbr_find(id);
    if (n) {
        return n;
    }
    /* free slot, or evict the least recently heard neighbour */
    nbr_t *victim = &s_nbr[0];
    for (int i = 0; i < IDS_MAX_NBRS; i++) {
        if (!s_nbr[i].used) {
            victim = &s_nbr[i];
            break;
        }
        if (s_nbr[i].last_ms < victim->last_ms) {
            victim = &s_nbr[i];
        }
    }
    memset(victim, 0, sizeof(*victim));
    victim->used = true;
    victim->id = id;
    victim->cost_q8 = MS_COST_INF;
    victim->hop = 0xFF;
    victim->last_ms = now_ms;
    return victim;
}

/* Returns true if seq is fresh (and records it). */
static bool replay_check(nbr_t *n, uint32_t seq)
{
    if (!n->seq_valid) {
        n->seq_valid = true;
        n->max_seq = seq;
        n->bitmap = 1;
        return true;
    }
    if (seq > n->max_seq) {
        uint32_t shift = seq - n->max_seq;
        n->bitmap = (shift >= 64) ? 1 : ((n->bitmap << shift) | 1);
        n->max_seq = seq;
        return true;
    }
    uint32_t diff = n->max_seq - seq;
    if (diff >= 64 || (n->bitmap & (1ULL << diff))) {
        return false;
    }
    n->bitmap |= (1ULL << diff);
    return true;
}

static bool asnl_contains(uint16_t id)
{
    for (int l = 0; l < 2; l++) {
        for (int i = 0; i < s_asnl_n[l]; i++) {
            if (s_asnl[l][i] == id) {
                return true;
            }
        }
    }
    return false;
}

void ids_set_asnl(const uint16_t *ids, int n)
{
    if (n > ASNL_MAX) {
        n = ASNL_MAX;
    }
    /* a claim must be absent from the last two signed lists */
    memcpy(s_asnl[1], s_asnl[0], sizeof(s_asnl[0]));
    s_asnl_n[1] = s_asnl_n[0];
    memcpy(s_asnl[0], ids, n * sizeof(uint16_t));
    s_asnl_n[0] = n;
    s_asnl_known = n > 0;
}

bool ids_on_frame(const ms_hdr_t *h, const void *payload, int8_t rssi,
                  uint32_t now_ms)
{
    nbr_t *n = nbr_get(h->tx, now_ms);
    n->frames++;
    if (!replay_check(n, h->txseq)) {
        n->replays++;
        return false;
    }
    n->rssi_sum += rssi;
    n->rssi_n++;
    n->last_ms = now_ms;

    if (h->type == MS_T_DATA || h->type == MS_T_REPORT) {
        /* does this frame satisfy a watchdog expectation? */
        for (int i = 0; i < IDS_MAX_PENDING; i++) {
            pending_t *p = &s_pend[i];
            if (p->used && p->nbr == h->tx && p->type == h->type &&
                    p->orig == h->orig && p->seq == h->seq) {
                if ((int32_t)(p->deadline_ms - now_ms) >= 0) {
                    n->over[s_cur]++;
                }
                p->used = false;
                break;
            }
        }
    } else if (h->type == MS_T_BEACON && h->len >= sizeof(ms_beacon_t)) {
        const ms_beacon_t *b = (const ms_beacon_t *)payload;
        n->beacons++;
        n->cost_q8 = b->cost_q8;
        n->parent = b->parent;
        n->hop = h->hop;
        if (h->hop == 1 && s_asnl_known && !asnl_contains(h->tx)) {
            n->bad_claims++;
        }
    }
    return true;
}

void ids_expect(uint16_t next, uint8_t type, uint16_t orig, uint16_t seq,
                bool own, uint32_t now_ms)
{
    if (next == MS_SINK_ID || next == MS_BCAST_ID || next == s_self) {
        return;
    }
    nbr_t *n = nbr_find(next);
    /* third-party monitors need a good link to overhear the forward; a
     * neighbour advertising no route is not expected to forward */
    const float min_prr = own ? 0.3f : 0.7f;
    if (!n || !n->prr_valid || n->prr < min_prr || n->cost_q8 == MS_COST_INF) {
        return;
    }
    for (int i = 0; i < IDS_MAX_PENDING; i++) {
        pending_t *p = &s_pend[i];
        if (p->used && p->nbr == next && p->type == type &&
                p->orig == orig && p->seq == seq) {
            return;
        }
    }
    pending_t *p = &s_pend[s_pend_next];
    s_pend_next = (s_pend_next + 1) % IDS_MAX_PENDING;
    *p = (pending_t) {
        .used = true, .own = own, .type = type, .nbr = next,
        .orig = orig, .seq = seq, .deadline_ms = now_ms + PENDING_MS,
    };
    if (n->hand[s_cur] < 255) {
        n->hand[s_cur]++;
    }
}

static inline uint8_t sat8(int v)
{
    return v < 0 ? 0 : (v > 255 ? 255 : (uint8_t)v);
}

int ids_end_window(uint16_t window, ms_rec_t *out, int max, uint32_t now_ms)
{
    (void)window;
    ms_rec_t recs[IDS_MAX_NBRS];
    uint8_t  verd[IDS_MAX_NBRS];
    int nrec = 0;

    for (int i = 0; i < IDS_MAX_PENDING; i++) {
        if (s_pend[i].used && (int32_t)(s_pend[i].deadline_ms - now_ms) < 0) {
            s_pend[i].used = false;
        }
    }

    for (int i = 0; i < IDS_MAX_NBRS; i++) {
        nbr_t *n = &s_nbr[i];
        if (!n->used) {
            continue;
        }
        int hand = 0, over = 0;
        for (int w = 0; w < N_SLIDE; w++) {
            hand += n->hand[w];
            over += n->over[w];
        }
        uint32_t idle = now_ms - n->last_ms;
        if (n->frames == 0 && hand == 0 && idle > 3000u * W_S) {
            if (idle > 6000u * W_S) {
                n->used = false;          /* forget long-gone neighbours */
            }
            continue;
        }
        float ratio = fminf(1.0f, n->beacons / EXP_BEACONS);
        n->prr = n->prr_valid ? 0.7f * n->prr + 0.3f * ratio : ratio;
        n->prr_valid = true;

        float rate = (float)n->frames / W_S;
        bool warm = n->warm >= CONFIG_MS_RATE_WARM;
        bool flood = warm && rate > fmaxf((float)CONFIG_MS_RATE_MIN_FPS,
                                          n->mu + RATE_K * fmaxf(n->dev, 0.5f));
        if (!flood) {                     /* freeze the baseline under attack */
            if (n->warm == 0) {
                n->mu = rate;
            } else {
                n->dev = 0.8f * n->dev + 0.2f * fabsf(rate - n->mu);
                n->mu = 0.8f * n->mu + 0.2f * rate;
            }
        }
        if (n->warm < 0xFFFF) {
            n->warm++;
        }

        ms_rec_t *r = &recs[nrec];
        r->nbr = n->id;
        r->handed = sat8(hand);
        r->overheard = sat8(over);
        r->prr_q8 = sat8((int)lroundf(n->prr * 255.0f));
        r->rssi = n->rssi_n ? (int8_t)lroundf((float)n->rssi_sum / n->rssi_n) : 0;
        r->rssi_n = sat8(n->rssi_n);
        r->rate = sat8((int)lroundf(rate));
        r->flags = (flood ? MS_REC_FLOOD : 0) | (warm ? MS_REC_RATE_WARM : 0) |
                   (s_asnl_known ? MS_REC_ASNL : 0) |
                   (n->beacons ? MS_REC_BEACON : 0) |
                   ((n->replays > 3 ? 3 : n->replays) << MS_REC_REPLAY_SH) |
                   ((n->bad_claims > 3 ? 3 : n->bad_claims) << MS_REC_CLAIM_SH);
        r->reserved = 0;
        verd[nrec] = ids_local_verdicts(r);
        if (verd[nrec] & IDS_A_FWD) {
            n->local_suspect = true;      /* local reaction: stop routing via n */
        }
        nrec++;

        n->frames = n->beacons = n->rssi_n = n->replays = 0;
        n->bad_claims = 0;
        n->rssi_sum = 0;
    }

    /* roll the sliding watchdog windows */
    s_cur = (s_cur + 1) % N_SLIDE;
    for (int i = 0; i < IDS_MAX_NBRS; i++) {
        s_nbr[i].hand[s_cur] = 0;
        s_nbr[i].over[s_cur] = 0;
    }

    /* records carrying alerts first, then by number of samples */
    int nout = 0;
    for (int pass = 0; pass < 2 && nout < max; pass++) {
        while (nout < max) {
            int best = -1;
            for (int i = 0; i < nrec; i++) {
                if (verd[i] == 0xFF || ((pass == 0) != (verd[i] != 0))) {
                    continue;
                }
                if (best < 0 || recs[i].rssi_n > recs[best].rssi_n) {
                    best = i;
                }
            }
            if (best < 0) {
                break;
            }
            out[nout++] = recs[best];
            verd[best] = 0xFF;            /* consumed */
        }
    }
    return nout;
}

int ids_neighbours(ids_nbr_info_t *out, int max)
{
    int k = 0;
    for (int i = 0; i < IDS_MAX_NBRS && k < max; i++) {
        const nbr_t *n = &s_nbr[i];
        if (!n->used) {
            continue;
        }
        out[k++] = (ids_nbr_info_t) {
            .id = n->id, .cost_q8 = n->cost_q8, .parent = n->parent,
            .hop = n->hop, .prr_q8 = sat8((int)lroundf(n->prr * 255.0f)),
            .prr_valid = n->prr_valid, .beacons = sat8(n->beacons),
            .rssi = n->rssi_n ? (int8_t)(n->rssi_sum / n->rssi_n) : 0,
            .last_ms = n->last_ms, .local_suspect = n->local_suspect,
        };
    }
    return k;
}
