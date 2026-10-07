/*
 * ESP-NOW broadcast mesh hosting MeshSentry.
 *
 * Threading: the Wi-Fi task's receive callback only copies frames into a
 * queue; all protocol and IDS state is owned by mesh_task. mesh_send_frame()
 * may be called from other tasks (attack emulation) and is serialised by a
 * mutex.
 *
 * Console output: machine-readable CSV lines prefixed with "MS," (see
 * tools/collect_logs.py), interleaved with normal ESP_LOG output.
 */
#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include <sys/param.h>
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "sdkconfig.h"
#include "ids.h"
#include "mesh.h"

static const char *TAG = "mesh";

#define W_MS            (CONFIG_MS_WINDOW_S * 1000u)
#define RXQ_LEN         24
#define N_DEFERRED      4
#define N_SEEN          64
#define N_TXCTR         8
#define MAX_BL          32
#define NO_PARENT       MS_BCAST_ID
#define HYSTERESIS_Q8   77                  /* 0.3 ETX */
#define SEQ_EPOCH_SHIFT 20

typedef struct {
    uint8_t  data[MS_MAX_FRAME];
    uint8_t  len;
    int8_t   rssi;
    uint32_t t_ms;
} rx_item_t;

typedef struct {
    bool     used;
    uint32_t due_ms;
    uint8_t  type;
    uint16_t orig, seq, next;
    uint8_t  hop;
    uint8_t  len;
    bool     needs_parent;               /* reports are routed when sent */
    uint8_t  payload[MS_MAX_PAYLOAD];
} deferred_t;

typedef struct {
    uint32_t tx_frames, tx_bytes, rx_frames, auth_fail, replays;
} stats_t;

static mesh_config_t     s_cfg;
static mesh_hooks_t      s_hooks;
static QueueHandle_t     s_rxq;
static SemaphoreHandle_t s_tx_lock;
static const uint8_t     BCAST_MAC[ESP_NOW_ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static uint32_t s_epoch;
static struct { uint16_t id; uint32_t ctr; } s_txctr[N_TXCTR];

/* routing */
static uint16_t s_parent = NO_PARENT;
static uint16_t s_cost_q8 = MS_COST_INF;
static uint8_t  s_hop = 0xFF;
static bool     s_joined;
static uint16_t s_data_seq, s_rep_seq;

/* control plane */
static uint32_t s_ctl_seen;
static uint32_t s_ctl_ctr;
static uint16_t s_bl[MAX_BL];
static int      s_n_bl;

/* window alignment to the sink clock */
static bool     s_synced;
static int32_t  s_clock_off;              /* sink_ms - local_ms */
static uint16_t s_window;

static uint64_t   s_seen[N_SEEN];
static int        s_seen_i;
static deferred_t s_def[N_DEFERRED];
static stats_t    s_stats;

/* ------------------------------------------------------------------ util */
uint32_t mesh_now_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static inline uint32_t sink_now_ms(void)
{
    return mesh_now_ms() + s_clock_off;
}

uint16_t mesh_self_id(void)
{
    return s_cfg.node_id;
}

void mesh_get_route(uint8_t *hop, uint16_t *cost_q8, uint16_t *parent)
{
    *hop = s_hop;
    *cost_q8 = s_cost_q8;
    *parent = s_parent;
}

static inline bool is_sink(void)
{
    return s_cfg.node_id == MS_SINK_ID;
}

/* Fusion and control-plane signing exist only in the sink image, so sensor
 * nodes do not carry the fusion tables. */
#if CONFIG_MS_ROLE_SINK
#define SINK_ONLY(stmt) stmt
#else
#define SINK_ONLY(stmt) do { } while (0)
#endif

static inline uint32_t rand_range(uint32_t lo, uint32_t hi)
{
    return lo + esp_random() % (hi - lo + 1);
}

#define CSV(fmt, ...) \
    printf("MS,%" PRIu32 ",%u," fmt "\n", sink_now_ms(), s_cfg.node_id, ##__VA_ARGS__)

static uint32_t next_txseq(uint16_t tx_id)
{
    int free_i = -1;
    for (int i = 0; i < N_TXCTR; i++) {
        if (s_txctr[i].ctr && s_txctr[i].id == tx_id) {
            return (s_epoch << SEQ_EPOCH_SHIFT) | (s_txctr[i].ctr++ & 0xFFFFF);
        }
        if (free_i < 0 && s_txctr[i].ctr == 0) {
            free_i = i;
        }
    }
    if (free_i < 0) {
        free_i = 0;
    }
    s_txctr[free_i].id = tx_id;
    s_txctr[free_i].ctr = 2;
    return (s_epoch << SEQ_EPOCH_SHIFT) | 1;
}

static bool blacklisted(uint16_t id)
{
    for (int i = 0; i < s_n_bl; i++) {
        if (s_bl[i] == id) {
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------- tx */
static esp_err_t radio_send(const uint8_t *buf, int len)
{
    esp_err_t err;
    for (int tries = 0; tries < 5; tries++) {
        err = esp_now_send(BCAST_MAC, buf, len);
        if (err != ESP_ERR_ESPNOW_NO_MEM) {
            break;
        }
        vTaskDelay(1);                     /* ESP-NOW queue full: back off */
    }
    if (err == ESP_OK) {
        s_stats.tx_frames++;
        s_stats.tx_bytes += len;
    }
    return err;
}

esp_err_t mesh_send_frame(ms_type_t type, uint16_t tx_id, uint16_t orig,
                          uint16_t seq, uint16_t next, uint8_t hop,
                          const void *payload, uint8_t len)
{
    if (len > MS_MAX_PAYLOAD) {
        return ESP_ERR_INVALID_SIZE;
    }
    uint8_t buf[MS_MAX_FRAME];
    xSemaphoreTake(s_tx_lock, portMAX_DELAY);
    ms_hdr_t *h = (ms_hdr_t *)buf;
    *h = (ms_hdr_t) {
        .magic = MS_MAGIC, .type = type, .tx = tx_id,
        .txseq = next_txseq(tx_id), .orig = orig, .seq = seq,
        .next = next, .hop = hop, .len = len,
    };
    memcpy(buf + sizeof(*h), payload, len);
    esp_err_t err = mesh_auth_tag(buf, sizeof(*h) + len, buf + sizeof(*h) + len);
    if (err == ESP_OK) {
        err = radio_send(buf, sizeof(*h) + len + MS_TAG_LEN);
    }
    xSemaphoreGive(s_tx_lock);
    return err;
}

esp_err_t mesh_send_raw(const uint8_t *frame, int len)
{
    xSemaphoreTake(s_tx_lock, portMAX_DELAY);
    esp_err_t err = radio_send(frame, len);
    xSemaphoreGive(s_tx_lock);
    return err;
}

static void defer(uint32_t delay_ms, uint8_t type, uint16_t orig, uint16_t seq,
                  uint16_t next, uint8_t hop, const void *payload, uint8_t len,
                  bool needs_parent)
{
    for (int i = 0; i < N_DEFERRED; i++) {
        deferred_t *d = &s_def[i];
        if (!d->used) {
            d->used = true;
            d->due_ms = mesh_now_ms() + delay_ms;
            d->type = type;
            d->orig = orig;
            d->seq = seq;
            d->next = next;
            d->hop = hop;
            d->len = len;
            d->needs_parent = needs_parent;
            memcpy(d->payload, payload, len);
            return;
        }
    }
    ESP_LOGW(TAG, "deferred queue full, dropping type %u", type);
}

static void run_deferred(uint32_t now)
{
    for (int i = 0; i < N_DEFERRED; i++) {
        deferred_t *d = &s_def[i];
        if (!d->used || (int32_t)(d->due_ms - now) > 0) {
            continue;
        }
        d->used = false;
        uint16_t next = d->next;
        if (d->needs_parent) {
            if (s_parent == NO_PARENT) {
                continue;
            }
            next = s_parent;
            ids_expect(next, d->type, d->orig, d->seq, true, now);
        }
        mesh_send_frame(d->type, s_cfg.node_id, d->orig, d->seq, next, d->hop,
                        d->payload, d->len);
    }
}

/* -------------------------------------------------------------- routing */
static void route_update(uint32_t now)
{
    if (is_sink()) {
        return;
    }
    ids_nbr_info_t nb[IDS_MAX_NBRS];
    int n = ids_neighbours(nb, IDS_MAX_NBRS);
    int best = -1;
    float best_c = 1e9f, cur_c = 1e9f;
    for (int i = 0; i < n; i++) {
        if (nb[i].cost_q8 == MS_COST_INF ||
                now - nb[i].last_ms > 3u * CONFIG_MS_BEACON_MS + 500u ||
                nb[i].parent == s_cfg.node_id) {
            continue;
        }
#if CONFIG_MS_MITIGATION
        if (blacklisted(nb[i].id) || nb[i].local_suspect) {
            continue;
        }
#endif
        /* unestimated links are only usable while bootstrapping */
        float prr = nb[i].prr_valid ? nb[i].prr_q8 / 255.0f
                    : (s_parent == NO_PARENT ? 0.7f : 0.0f);
        if (prr < 0.6f) {
            continue;
        }
        float c = nb[i].cost_q8 + 256.0f / prr;       /* path ETX (q8) */
        if (nb[i].id == s_parent) {
            cur_c = c;
        }
        if (c < best_c) {
            best_c = c;
            best = i;
        }
    }
    if (best < 0) {
        s_parent = NO_PARENT;
        s_cost_q8 = MS_COST_INF;
        s_hop = 0xFF;
        return;
    }
    if (s_parent == NO_PARENT || cur_c >= 1e9f || best_c < cur_c - HYSTERESIS_Q8) {
        s_parent = nb[best].id;
        cur_c = best_c;
    }
    s_cost_q8 = cur_c > 65534.0f ? 65534 : (uint16_t)cur_c;
    for (int i = 0; i < n; i++) {
        if (nb[i].id == s_parent) {
            s_hop = nb[i].hop + 1;
        }
    }
    s_joined = true;
}

/* ------------------------------------------------------------- sending */
static void send_beacon(uint32_t now)
{
    route_update(now);
    if (s_cfg.passive || (!is_sink() && !s_joined)) {
        return;
    }
    uint8_t hop = is_sink() ? 0 : s_hop;
    uint16_t cost = is_sink() ? 0 : s_cost_q8;
    uint16_t parent = s_parent;
    if (s_hooks.beacon_override) {
        s_hooks.beacon_override(&hop, &cost, &parent);
    }
    /* joined nodes keep beaconing; cost = inf poisons a lost route */
    ms_beacon_t b = { .cost_q8 = cost, .parent = parent, .uptime_s = now / 1000 };
    mesh_send_frame(MS_T_BEACON, s_cfg.node_id, s_cfg.node_id, 0, MS_BCAST_ID,
                    hop, &b, sizeof(b));
}

static void send_data(uint32_t now)
{
    uint16_t seq = s_data_seq++;
    CSV("GEN,%u", seq);
    if (s_parent == NO_PARENT) {
        return;
    }
    ms_data_t d = { .t_ms = sink_now_ms(), .temp_c10 = 215, .vbat_mv = 3700 };
    ids_expect(s_parent, MS_T_DATA, s_cfg.node_id, seq, true, now);
    mesh_send_frame(MS_T_DATA, s_cfg.node_id, s_cfg.node_id, seq, s_parent, 1,
                    &d, sizeof(d));
}

static void log_record(const char *kind, uint16_t window, uint16_t mon,
                       const ms_rec_t *r)
{
    CSV("%s,%u,%u,%u,%u,%u,%u,%d,%u,%u,%u", kind, window, mon, r->nbr,
        r->handed, r->overheard, r->prr_q8, r->rssi, r->rssi_n, r->rate,
        r->flags);
}

static void end_window(uint32_t now)
{
    uint8_t buf[sizeof(ms_report_t) + MS_MAX_RECS * sizeof(ms_rec_t)];
    ms_report_t *rep = (ms_report_t *)buf;
    int n = ids_end_window(s_window, rep->rec, MS_MAX_RECS, now);
    rep->window = s_window;
    rep->n_rec = n;
    rep->reserved = 0;
    for (int i = 0; i < n; i++) {
        log_record("REC", s_window, s_cfg.node_id, &rep->rec[i]);
    }
    CSV("STAT,%u,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%u,%u",
        s_window, s_stats.tx_frames, s_stats.tx_bytes, s_stats.rx_frames,
        s_stats.auth_fail, s_stats.replays, s_parent, s_hop);
    if (is_sink()) {
        SINK_ONLY(ids_fusion_add_report(s_cfg.node_id, s_window, rep->rec, n));
    } else if (s_synced && !s_cfg.passive) {
        defer(rand_range(200, 3000), MS_T_REPORT, s_cfg.node_id, s_rep_seq++,
              NO_PARENT, 1, buf, sizeof(ms_report_t) + n * sizeof(ms_rec_t), true);
    }
#if CONFIG_MS_MITIGATION
    route_update(now);
#endif
}

static void on_decision(uint16_t id, ids_alert_t type, uint16_t window)
{
    CSV("DEC,%u,%u,%s", window, id, ids_alert_name(type));
}

#if CONFIG_MS_ROLE_SINK
static void send_ctl(uint32_t now)
{
    uint8_t buf[MS_MAX_PAYLOAD];
    ms_ctl_t *c = (ms_ctl_t *)buf;
    const int max_ids = (MS_MAX_PAYLOAD - sizeof(ms_ctl_t) - MS_SIG_LEN) / 2;
    c->ctl_seq = (s_epoch << SEQ_EPOCH_SHIFT) | (++s_ctl_ctr & 0xFFFFF);
    c->sink_ms = sink_now_ms();
    c->n_asnl = 0;
    c->n_bl = 0;
    /* signed sink-neighbour list; withheld while the network bootstraps */
    if (sink_now_ms() >= 2 * W_MS) {
        ids_nbr_info_t nb[IDS_MAX_NBRS];
        int n = ids_neighbours(nb, IDS_MAX_NBRS);
        for (int i = 0; i < n && c->n_asnl < max_ids; i++) {
            if ((nb[i].prr_valid && nb[i].prr_q8 >= 77) || nb[i].beacons >= 2) {
                c->ids[c->n_asnl++] = nb[i].id;
            }
        }
    }
#if CONFIG_MS_MITIGATION
    uint16_t bl[MAX_BL];
    c->n_bl = ids_fusion_blacklist(bl, MIN(MAX_BL, max_ids - c->n_asnl));
    memcpy((uint8_t *)c->ids + 2 * c->n_asnl, bl, 2 * c->n_bl);
#endif
    size_t body = sizeof(ms_ctl_t) + 2 * (c->n_asnl + c->n_bl);
    if (mesh_ctl_sign(buf, body, buf + body) != ESP_OK) {
        ESP_LOGE(TAG, "ctl signing failed");
        return;
    }
    mesh_send_frame(MS_T_CTL, s_cfg.node_id, s_cfg.node_id,
                    (uint16_t)c->ctl_seq, MS_BCAST_ID, 0, buf, body + MS_SIG_LEN);
}
#else
static void send_ctl(uint32_t now)
{
    (void)now;
}
#endif

/* ------------------------------------------------------------- receive */
static bool dedupe(const ms_hdr_t *h)
{
    uint64_t key = ((uint64_t)h->type << 32) | ((uint32_t)h->orig << 16) | h->seq;
    for (int i = 0; i < N_SEEN; i++) {
        if (s_seen[i] == key) {
            return true;
        }
    }
    s_seen[s_seen_i] = key;
    s_seen_i = (s_seen_i + 1) % N_SEEN;
    return false;
}

static void deliver(const ms_hdr_t *h, const uint8_t *payload)
{
    if (h->type == MS_T_DATA && h->len >= sizeof(ms_data_t)) {
        const ms_data_t *d = (const ms_data_t *)payload;
        CSV("DLV,%u,%u,%" PRIu32 ",%u", h->orig, h->seq, d->t_ms, h->hop);
    } else if (h->type == MS_T_REPORT && h->len >= sizeof(ms_report_t)) {
        const ms_report_t *r = (const ms_report_t *)payload;
        int n = r->n_rec;
        if (sizeof(ms_report_t) + n * sizeof(ms_rec_t) > h->len) {
            return;
        }
        for (int i = 0; i < n; i++) {
            log_record("RPT", r->window, h->orig, &r->rec[i]);
        }
        SINK_ONLY(ids_fusion_add_report(h->orig, r->window, r->rec, n));
    }
}

static void forward(const ms_hdr_t *h, const uint8_t *payload, uint32_t now)
{
    if (dedupe(h)) {
        return;
    }
    if (is_sink()) {
        deliver(h, payload);
        return;
    }
    if (h->hop >= MS_MAX_HOPS || s_parent == NO_PARENT) {
        return;
    }
    if (s_hooks.drop_forward && s_hooks.drop_forward(h)) {
        return;
    }
    ids_expect(s_parent, h->type, h->orig, h->seq, true, now);
    mesh_send_frame(h->type, s_cfg.node_id, h->orig, h->seq, s_parent,
                    h->hop + 1, payload, h->len);
}

static void handle_ctl(const ms_hdr_t *h, const uint8_t *payload, uint32_t now)
{
    if (h->len < sizeof(ms_ctl_t) + MS_SIG_LEN) {
        return;
    }
    const ms_ctl_t *c = (const ms_ctl_t *)payload;
    size_t body = sizeof(ms_ctl_t) + 2 * (c->n_asnl + c->n_bl);
    if (body + MS_SIG_LEN != h->len || c->ctl_seq <= s_ctl_seen) {
        return;
    }
    if (!mesh_ctl_verify(payload, body, payload + body)) {
        ESP_LOGW(TAG, "forged control frame from %u", h->tx);
        return;
    }
    s_ctl_seen = c->ctl_seq;
    /* ~5 ms per hop of flooding latency */
    s_clock_off = (int32_t)(c->sink_ms + 5u * (h->hop + 1) - now);
    if (!s_synced) {
        s_synced = true;
        s_window = sink_now_ms() / W_MS;
        ESP_LOGI(TAG, "synchronised to sink clock, window %u", s_window);
    }
    if (c->n_asnl) {
        uint16_t asnl[MS_MAX_PAYLOAD / 2];       /* aligned copy */
        memcpy(asnl, c->ids, 2 * c->n_asnl);
        ids_set_asnl(asnl, c->n_asnl);
    }
    s_n_bl = MIN(c->n_bl, MAX_BL);
    memcpy(s_bl, (const uint8_t *)c->ids + 2 * c->n_asnl, 2 * s_n_bl);
    if (!is_sink()) {
        defer(rand_range(2, 20), MS_T_CTL, h->orig, h->seq, MS_BCAST_ID,
              h->hop + 1, payload, h->len, false);
    }
}

static void process_rx(const rx_item_t *it)
{
    if (s_hooks.on_raw_rx) {
        s_hooks.on_raw_rx(it->data, it->len);
    }
    if (s_cfg.passive || it->len < MS_OVERHEAD) {
        return;
    }
    const ms_hdr_t *h = (const ms_hdr_t *)it->data;
    if (h->magic != MS_MAGIC || h->len + MS_OVERHEAD != it->len) {
        return;
    }
    const uint8_t *payload = it->data + sizeof(*h);
    if (!mesh_auth_verify(it->data, sizeof(*h) + h->len, payload + h->len)) {
        s_stats.auth_fail++;
        return;
    }
    if (h->tx == s_cfg.node_id) {
        return;
    }
    s_stats.rx_frames++;
    if (!ids_on_frame(h, payload, it->rssi, it->t_ms)) {
        s_stats.replays++;
        return;
    }
    switch (h->type) {
    case MS_T_BEACON:
        route_update(it->t_ms);
        break;
    case MS_T_DATA:
    case MS_T_REPORT:
        if (h->next == s_cfg.node_id) {
            forward(h, payload, it->t_ms);
        } else {
            ids_expect(h->next, h->type, h->orig, h->seq, false, it->t_ms);
        }
        break;
    case MS_T_CTL:
        handle_ctl(h, payload, it->t_ms);
        break;
    default:
        break;
    }
}

/* Wi-Fi task context: copy and hand over to mesh_task. */
static void espnow_recv_cb(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
    if (len <= 0 || len > MS_MAX_FRAME) {
        return;
    }
    rx_item_t it = { .len = (uint8_t)len, .rssi = info->rx_ctrl->rssi,
                     .t_ms = mesh_now_ms() };
    memcpy(it.data, data, len);
    xQueueSend(s_rxq, &it, 0);
}

static void espnow_send_cb(const esp_now_send_info_t *tx_info, esp_now_send_status_t status)
{
    (void)tx_info;
    (void)status;
}

/* ---------------------------------------------------------------- task */
static void mesh_task(void *arg)
{
    static rx_item_t it;
    uint32_t now = mesh_now_ms();
    uint32_t t_beacon = now + rand_range(0, CONFIG_MS_BEACON_MS);
    uint32_t t_data = now + 10000 + rand_range(0, CONFIG_MS_DATA_MS);
    /* window k spans [k*W, (k+1)*W) of the sink clock */
    uint32_t t_window = (now / W_MS + 1) * W_MS;
    if (is_sink()) {
        s_window = now / W_MS;
    }
    uint32_t t_ctl = now + CONFIG_MS_CTL_OFFSET_MS;
    uint32_t t_decide = 0;
    uint16_t decide_w = 0;
    bool was_synced = s_synced;

    for (;;) {
        now = mesh_now_ms();
        uint32_t next = t_beacon;
        if ((int32_t)(t_window - next) < 0) next = t_window;
        if (!s_cfg.passive && !is_sink() && (int32_t)(t_data - next) < 0) next = t_data;
        for (int i = 0; i < N_DEFERRED; i++) {
            if (s_def[i].used && (int32_t)(s_def[i].due_ms - next) < 0) {
                next = s_def[i].due_ms;
            }
        }
        int32_t wait = (int32_t)(next - now);
        /* timers are checked after every frame so floods cannot starve them */
        if (xQueueReceive(s_rxq, &it, wait > 0 ? pdMS_TO_TICKS(wait) : 0) == pdTRUE) {
            process_rx(&it);
        }
        now = mesh_now_ms();
        run_deferred(now);

        if ((int32_t)(now - t_beacon) >= 0) {
            send_beacon(now);
            t_beacon = now + CONFIG_MS_BEACON_MS - 100 + rand_range(0, 200);
        }
        if (!s_cfg.passive && !is_sink() && (int32_t)(now - t_data) >= 0) {
            send_data(now);
            t_data += CONFIG_MS_DATA_MS;
        }
        if (s_synced && !was_synced) {      /* re-align windows to the sink */
            was_synced = true;
            t_window = now + ((s_window + 1) * W_MS - sink_now_ms());
        }
        if ((int32_t)(now - t_window) >= 0) {
            end_window(now);
            if (is_sink()) {
                decide_w = s_window;
                t_decide = now + CONFIG_MS_DECIDE_DELAY_MS;
            }
            s_window++;
            t_window += W_MS;
        }
        if (is_sink()) {
            if (t_decide && (int32_t)(now - t_decide) >= 0) {
                SINK_ONLY(ids_fusion_decide(decide_w, on_decision));
                t_decide = 0;
            }
            if ((int32_t)(now - t_ctl) >= 0) {
                send_ctl(now);
                t_ctl += W_MS;
            }
        }
    }
}

static uint32_t load_epoch(void)
{
    nvs_handle_t h;
    uint32_t e = 0;
    if (nvs_open("meshsentry", NVS_READWRITE, &h) == ESP_OK) {
        nvs_get_u32(h, "epoch", &e);
        e = (e + 1) & 0xFFF;
        nvs_set_u32(h, "epoch", e);
        nvs_commit(h);
        nvs_close(h);
    }
    return e;
}

esp_err_t mesh_start(const mesh_config_t *cfg, const mesh_hooks_t *hooks)
{
    s_cfg = *cfg;
    if (hooks) {
        s_hooks = *hooks;
    }
    s_epoch = load_epoch();
    if (is_sink()) {
        s_synced = true;
        s_hop = 0;
        s_cost_q8 = 0;
        s_joined = true;
    }
    s_rxq = xQueueCreate(RXQ_LEN, sizeof(rx_item_t));
    s_tx_lock = xSemaphoreCreateMutex();
    if (!s_rxq || !s_tx_lock) {
        return ESP_ERR_NO_MEM;
    }
    ESP_ERROR_CHECK(mesh_auth_init());
    ids_init(s_cfg.node_id);
    if (is_sink()) {
        SINK_ONLY(ids_fusion_init());
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t wc = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wc));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_channel(CONFIG_MS_CHANNEL, WIFI_SECOND_CHAN_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_max_tx_power(CONFIG_MS_TX_POWER_DBM * 4));

    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_recv_cb(espnow_recv_cb));
    ESP_ERROR_CHECK(esp_now_register_send_cb(espnow_send_cb));
    esp_now_peer_info_t peer = { .channel = 0, .ifidx = WIFI_IF_STA, .encrypt = false };
    memcpy(peer.peer_addr, BCAST_MAC, ESP_NOW_ETH_ALEN);
    ESP_ERROR_CHECK(esp_now_add_peer(&peer));

    ESP_LOGI(TAG, "node %u (%s) epoch %" PRIu32 " on channel %d",
             s_cfg.node_id, is_sink() ? "sink" : (s_cfg.passive ? "passive" : "node"),
             s_epoch, CONFIG_MS_CHANNEL);
    BaseType_t ok = xTaskCreatePinnedToCore(mesh_task, "mesh", 8192, NULL, 5,
                                            NULL, 1);
    return ok == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}
