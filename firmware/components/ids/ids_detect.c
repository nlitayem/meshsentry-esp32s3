/*
 * Local detectors applied to one per-neighbour feature record.
 * Mirrors local_verdicts()/eligible_types() in sim/meshsentry/ids.py.
 */
#include <math.h>
#include "sdkconfig.h"
#include "ids.h"

#define FWD_ALPHA   (CONFIG_MS_FWD_ALPHA_PPM / 1e6)
#define FWD_Q       (CONFIG_MS_FWD_Q_PCT / 100.0)

double ids_binom_cdf(int k, int n, double q)
{
    if (k >= n) {
        return 1.0;
    }
    if (q < 1e-6) {
        q = 1e-6;
    } else if (q > 1.0 - 1e-6) {
        q = 1.0 - 1e-6;
    }
    /* pmf(i+1) = pmf(i) * (n-i)/(i+1) * q/(1-q), pmf(0) = (1-q)^n */
    double pmf = pow(1.0 - q, n);
    double cdf = pmf;
    const double r = q / (1.0 - q);
    for (int i = 0; i < k; i++) {
        pmf *= (double)(n - i) / (double)(i + 1) * r;
        cdf += pmf;
    }
    return cdf;
}

static inline int rec_replays(const ms_rec_t *r)
{
    return (r->flags >> MS_REC_REPLAY_SH) & 0x3;
}

static inline int rec_claims(const ms_rec_t *r)
{
    return (r->flags >> MS_REC_CLAIM_SH) & 0x3;
}

uint8_t ids_eligible(const ms_rec_t *r)
{
    uint8_t e = 0;
    if (r->handed >= CONFIG_MS_MIN_HANDED) {
        e |= IDS_A_FWD;
    }
    if (r->flags & MS_REC_RATE_WARM) {
        e |= IDS_A_FLOOD;
    }
    if ((r->flags & MS_REC_ASNL) && (r->flags & MS_REC_BEACON)) {
        e |= IDS_A_ROUTE;
    }
    if (r->rssi_n > 0 || rec_replays(r) > 0) {
        e |= IDS_A_REPLAY;
    }
    return e;
}

uint8_t ids_local_verdicts(const ms_rec_t *r)
{
    uint8_t v = 0;
    if (r->handed >= CONFIG_MS_MIN_HANDED) {
        double q = FWD_Q * (r->prr_q8 / 255.0);
        if (ids_binom_cdf(r->overheard, r->handed, q) < FWD_ALPHA) {
            v |= IDS_A_FWD;
        }
    }
    if (r->flags & MS_REC_FLOOD) {
        v |= IDS_A_FLOOD;
    }
    if ((r->flags & MS_REC_ASNL) && rec_claims(r) >= CONFIG_MS_ROUTE_MIN_CLAIMS) {
        v |= IDS_A_ROUTE;
    }
    if (rec_replays(r) >= CONFIG_MS_REPLAY_MIN) {
        v |= IDS_A_REPLAY;
    }
    return v;
}

const char *ids_alert_name(ids_alert_t a)
{
    switch (a) {
    case IDS_A_FWD:    return "FWD";
    case IDS_A_FLOOD:  return "FLOOD";
    case IDS_A_ROUTE:  return "ROUTE";
    case IDS_A_REPLAY: return "REPLAY";
    case IDS_A_SYBIL:  return "SYBIL";
    default:           return "?";
    }
}
