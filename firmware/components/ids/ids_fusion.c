/*
 * Sink-side fusion: trust-weighted consensus over monitor reports plus the
 * RSSI-signature Sybil detector. Mirrors class Fusion in
 * sim/meshsentry/ids.py.
 *
 * Called only from the sink's mesh task.
 */
#include <string.h>
#include <math.h>
#include "sdkconfig.h"
#include "ids.h"

#define MAX_MON        32
#define MAX_VOTES      160
#define MAX_IDS        64
#define MAX_PAIRS      128
#define MAX_DECLARED   64
#define MAX_BL         32

#define VOTE_TAU       (CONFIG_MS_VOTE_TAU_PCT / 100.0f)
#define MASS_MIN       (CONFIG_MS_MASS_MIN_X10 / 10.0f)
#define TRUST_HI       0.75f
#define TRUST_LO       0.25f
#define SYBIL_DELTA    (CONFIG_MS_SYBIL_DELTA_X10 / 10.0f)
#define SYBIL_MIN_N    3
#define SYBIL_MIN_TRUST 0.4f
#define RSSI_NONE      127

typedef struct {
    uint16_t mon;
    uint8_t  n;
    ms_rec_t rec[MS_MAX_RECS];
} report_t;

typedef struct {
    bool     valid;
    uint16_t window;
    uint8_t  n_mon;
    report_t rep[MAX_MON];
} slot_t;

typedef struct {
    uint16_t id;
    float    alpha, beta;
} trust_t;

typedef struct {
    uint16_t id;
    uint8_t  type;
    uint8_t  n_acc;
    float    m_a, m_t;
} vote_t;

typedef struct {
    uint16_t a, b;
    uint8_t  hist;    /* last 3 windows, bit 0 = newest */
    bool     used;
    bool     seen;
} pair_t;

static slot_t   s_slot[2];
static trust_t  s_trust[MAX_MON];
static int      s_n_trust;
static vote_t   s_votes[MAX_VOTES];
static pair_t   s_pairs[MAX_PAIRS];
static struct { uint16_t id; uint8_t type; } s_decl[MAX_DECLARED];
static int      s_n_decl;
static uint16_t s_bl[MAX_BL];
static int      s_n_bl;
static int8_t   s_rssi_tab[MAX_IDS][MAX_MON];
static uint16_t s_tab_ids[MAX_IDS];

void ids_fusion_init(void)
{
    memset(s_slot, 0, sizeof(s_slot));
    memset(s_trust, 0, sizeof(s_trust));
    memset(s_pairs, 0, sizeof(s_pairs));
    s_n_trust = s_n_decl = s_n_bl = 0;
}

static trust_t *trust_get(uint16_t mon)
{
    for (int i = 0; i < s_n_trust; i++) {
        if (s_trust[i].id == mon) {
            return &s_trust[i];
        }
    }
    if (s_n_trust < MAX_MON) {
        s_trust[s_n_trust] = (trust_t) { .id = mon };
        return &s_trust[s_n_trust++];
    }
    return NULL;
}

float ids_fusion_trust(uint16_t mon)
{
    trust_t *t = trust_get(mon);
    if (!t) {
        return 0.5f;
    }
    /* Beta reputation: E[Beta(alpha+1, beta+1)] */
    return (t->alpha + 1.0f) / (t->alpha + t->beta + 2.0f);
}

void ids_fusion_add_report(uint16_t mon, uint16_t window,
                           const ms_rec_t *rec, int n)
{
    slot_t *s = &s_slot[window & 1];
    if (!s->valid || s->window != window) {
        memset(s, 0, sizeof(*s));
        s->valid = true;
        s->window = window;
    }
    report_t *r = NULL;
    for (int i = 0; i < s->n_mon; i++) {
        if (s->rep[i].mon == mon) {
            r = &s->rep[i];
        }
    }
    if (!r) {
        if (s->n_mon >= MAX_MON) {
            return;
        }
        r = &s->rep[s->n_mon++];
    }
    if (n > MS_MAX_RECS) {
        n = MS_MAX_RECS;
    }
    r->mon = mon;
    r->n = n;
    memcpy(r->rec, rec, n * sizeof(ms_rec_t));
}

static bool declare(uint16_t id, uint8_t type)
{
    for (int i = 0; i < s_n_decl; i++) {
        if (s_decl[i].id == id && s_decl[i].type == type) {
            return false;
        }
    }
    if (s_n_decl < MAX_DECLARED) {
        s_decl[s_n_decl].id = id;
        s_decl[s_n_decl].type = type;
        s_n_decl++;
    }
    if (type & IDS_BLACKLIST_MASK) {
        bool listed = false;
        for (int i = 0; i < s_n_bl; i++) {
            listed |= s_bl[i] == id;
        }
        if (!listed && s_n_bl < MAX_BL) {
            s_bl[s_n_bl++] = id;
        }
    }
    return true;
}

static vote_t *vote_get(int *n_votes, uint16_t id, uint8_t type)
{
    for (int i = 0; i < *n_votes; i++) {
        if (s_votes[i].id == id && s_votes[i].type == type) {
            return &s_votes[i];
        }
    }
    if (*n_votes >= MAX_VOTES) {
        return NULL;
    }
    s_votes[*n_votes] = (vote_t) { .id = id, .type = type };
    return &s_votes[(*n_votes)++];
}

static pair_t *pair_get(uint16_t a, uint16_t b)
{
    pair_t *free_slot = NULL;
    for (int i = 0; i < MAX_PAIRS; i++) {
        if (s_pairs[i].used && s_pairs[i].a == a && s_pairs[i].b == b) {
            return &s_pairs[i];
        }
        if (!free_slot && (!s_pairs[i].used || s_pairs[i].hist == 0)) {
            free_slot = &s_pairs[i];
        }
    }
    if (free_slot) {
        *free_slot = (pair_t) { .a = a, .b = b, .used = true };
    }
    return free_slot;
}

static int sybil_detect(const slot_t *s, ids_decision_cb_t cb)
{
    int n_ids = 0, n_new = 0;
    memset(s_rssi_tab, RSSI_NONE, sizeof(s_rssi_tab));
    for (int m = 0; m < s->n_mon; m++) {
        const report_t *r = &s->rep[m];
        if (ids_fusion_trust(r->mon) < SYBIL_MIN_TRUST) {
            continue;
        }
        for (int k = 0; k < r->n; k++) {
            const ms_rec_t *rec = &r->rec[k];
            if (rec->rssi_n < SYBIL_MIN_N) {
                continue;
            }
            int idx = -1;
            for (int i = 0; i < n_ids; i++) {
                if (s_tab_ids[i] == rec->nbr) {
                    idx = i;
                }
            }
            if (idx < 0 && n_ids < MAX_IDS) {
                idx = n_ids;
                s_tab_ids[n_ids++] = rec->nbr;
            }
            if (idx >= 0) {
                s_rssi_tab[idx][m] = rec->rssi;
            }
        }
    }
    for (int i = 0; i < MAX_PAIRS; i++) {
        s_pairs[i].seen = false;
    }
    for (int x = 0; x < n_ids; x++) {
        for (int y = x + 1; y < n_ids; y++) {
            int common = 0;
            float ss = 0.0f;
            for (int m = 0; m < s->n_mon; m++) {
                if (s_rssi_tab[x][m] != RSSI_NONE && s_rssi_tab[y][m] != RSSI_NONE) {
                    float d = (float)(s_rssi_tab[x][m] - s_rssi_tab[y][m]);
                    ss += d * d;
                    common++;
                }
            }
            if (common < CONFIG_MS_SYBIL_MIN_MONITORS) {
                continue;
            }
            uint16_t a = s_tab_ids[x] < s_tab_ids[y] ? s_tab_ids[x] : s_tab_ids[y];
            uint16_t b = s_tab_ids[x] < s_tab_ids[y] ? s_tab_ids[y] : s_tab_ids[x];
            bool close = sqrtf(ss / common) < SYBIL_DELTA;
            pair_t *p = pair_get(a, b);
            if (!p) {
                continue;
            }
            p->hist = ((p->hist << 1) | (close ? 1 : 0)) & 0x7;
            p->seen = true;
        }
    }
    for (int i = 0; i < MAX_PAIRS; i++) {
        pair_t *p = &s_pairs[i];
        if (!p->used) {
            continue;
        }
        if (!p->seen) {
            p->hist = (p->hist << 1) & 0x7;
        }
        if (__builtin_popcount(p->hist) >= 2) {
            if (declare(p->a, IDS_A_SYBIL) && cb) {
                cb(p->a, IDS_A_SYBIL, s->window);
                n_new++;
            }
            if (declare(p->b, IDS_A_SYBIL) && cb) {
                cb(p->b, IDS_A_SYBIL, s->window);
                n_new++;
            }
        }
    }
    return n_new;
}

int ids_fusion_decide(uint16_t window, ids_decision_cb_t cb)
{
    slot_t *s = &s_slot[window & 1];
    if (!s->valid || s->window != window) {
        return 0;
    }
    int n_votes = 0, n_new = 0;

    /* pass 1: accumulate trust-weighted votes */
    for (int m = 0; m < s->n_mon; m++) {
        const report_t *r = &s->rep[m];
        float t = ids_fusion_trust(r->mon);
        for (int k = 0; k < r->n; k++) {
            uint8_t e = ids_eligible(&r->rec[k]);
            uint8_t v = ids_local_verdicts(&r->rec[k]);
            for (uint8_t type = 1; type <= IDS_A_REPLAY; type <<= 1) {
                if (!(e & type)) {
                    continue;
                }
                vote_t *vt = vote_get(&n_votes, r->rec[k].nbr, type);
                if (!vt) {
                    continue;
                }
                vt->m_t += t;
                if (v & type) {
                    vt->m_a += t;
                    vt->n_acc++;
                }
            }
        }
    }

    /* decisions */
    for (int i = 0; i < n_votes; i++) {
        vote_t *vt = &s_votes[i];
        float score = vt->m_t > 0 ? vt->m_a / vt->m_t : 0.0f;
        /* replays carry cryptographic evidence: a trusted quorum suffices */
        float thr = vt->type == IDS_A_REPLAY ? 0.0f : VOTE_TAU;
        if (vt->m_a >= MASS_MIN && score >= thr &&
                vt->n_acc >= CONFIG_MS_MIN_ACCUSERS) {
            if (declare(vt->id, vt->type) && cb) {
                cb(vt->id, (ids_alert_t)vt->type, window);
                n_new++;
            }
        }
        vt->m_t = score;  /* reuse field: keep the score for pass 2 */
    }

    /* pass 2: Beta-reputation update on clear-cut decisions */
    for (int m = 0; m < s->n_mon; m++) {
        const report_t *r = &s->rep[m];
        trust_t *tr = trust_get(r->mon);
        if (!tr) {
            continue;
        }
        for (int k = 0; k < r->n; k++) {
            uint8_t e = ids_eligible(&r->rec[k]);
            uint8_t v = ids_local_verdicts(&r->rec[k]);
            for (uint8_t type = IDS_A_FWD; type <= IDS_A_ROUTE; type <<= 1) {
                if (!(e & type)) {
                    continue;
                }
                vote_t *vt = vote_get(&n_votes, r->rec[k].nbr, type);
                if (!vt) {
                    continue;
                }
                bool accused = v & type;
                if (vt->m_t >= TRUST_HI) {
                    *(accused ? &tr->alpha : &tr->beta) += 1.0f;
                } else if (vt->m_t <= TRUST_LO) {
                    *(accused ? &tr->beta : &tr->alpha) += 1.0f;
                }
            }
        }
    }

    n_new += sybil_detect(s, cb);
    s->valid = false;
    return n_new;
}

int ids_fusion_blacklist(uint16_t *out, int max)
{
    int n = s_n_bl < max ? s_n_bl : max;
    memcpy(out, s_bl, n * sizeof(uint16_t));
    return n;
}
