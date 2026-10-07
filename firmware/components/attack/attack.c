/*
 * Testbed attack emulation. Each mode reproduces the corresponding attacker
 * of the simulation study (sim/meshsentry/sim.py) so that simulation and
 * testbed results are comparable.
 */
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_random.h"
#include "sdkconfig.h"
#include "attack.h"

#if CONFIG_MS_ROLE_ATTACKER

static const char *TAG = "attack";

static inline bool active(void)
{
    return mesh_now_ms() >= CONFIG_MS_ATTACK_START_S * 1000u;
}

#if CONFIG_MS_ATTACK_SELFWD
static bool drop_selective(const ms_hdr_t *h)
{
    (void)h;
    return active() && (esp_random() % 100) < CONFIG_MS_ATTACK_DROP_PCT;
}
#endif

#if CONFIG_MS_ATTACK_SINKHOLE
static bool drop_all(const ms_hdr_t *h)
{
    (void)h;
    return active();
}

static void claim_hop1(uint8_t *hop, uint16_t *cost_q8, uint16_t *parent)
{
    if (active()) {
        *hop = 1;
        *cost_q8 = 256;
        *parent = MS_SINK_ID;
    }
}
#endif

#if CONFIG_MS_ATTACK_REPLAY
#define STORE 64
static uint8_t s_store[STORE][MS_MAX_FRAME];
static uint8_t s_store_len[STORE];
static int     s_store_n;

static void record(const uint8_t *frame, int len)
{
    const ms_hdr_t *h = (const ms_hdr_t *)frame;
    if (active() || len < (int)MS_OVERHEAD || h->magic != MS_MAGIC ||
            (h->type != MS_T_BEACON && h->type != MS_T_DATA)) {
        return;
    }
    int i = s_store_n < STORE ? s_store_n++ : (int)(esp_random() % STORE);
    memcpy(s_store[i], frame, len);
    s_store_len[i] = len;
}

static void replay_task(void *arg)
{
    while (!active()) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    ESP_LOGW(TAG, "replay started with %d recorded frames", s_store_n);
    for (;;) {
        if (s_store_n) {
            int i = esp_random() % s_store_n;
            mesh_send_raw(s_store[i], s_store_len[i]);   /* verbatim */
        }
        vTaskDelay(pdMS_TO_TICKS(1000 / CONFIG_MS_ATTACK_REPLAY_FPS));
    }
}
#endif

#if CONFIG_MS_ATTACK_FLOOD
static void flood_task(void *arg)
{
    uint8_t junk[50 - MS_OVERHEAD] = {0};
    uint16_t seq = 0;
    while (!active()) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    ESP_LOGW(TAG, "flooding at %d frames/s", CONFIG_MS_ATTACK_FLOOD_FPS);
    const TickType_t period = pdMS_TO_TICKS(1000 / CONFIG_MS_ATTACK_FLOOD_FPS);
    TickType_t last = xTaskGetTickCount();
    for (;;) {
        mesh_send_frame(MS_T_JUNK, mesh_self_id(), mesh_self_id(), seq++,
                        MS_BCAST_ID, 0, junk, sizeof(junk));
        vTaskDelayUntil(&last, period ? period : 1);
    }
}
#endif

#if CONFIG_MS_ATTACK_SYBIL
static void sybil_task(void *arg)
{
    while (!active()) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    ESP_LOGW(TAG, "advertising %d Sybil identities", CONFIG_MS_ATTACK_N_SYBIL);
    for (;;) {
        uint8_t hop;
        uint16_t cost, parent;
        mesh_get_route(&hop, &cost, &parent);
        for (int i = 0; i < CONFIG_MS_ATTACK_N_SYBIL; i++) {
            uint16_t fake = 0x7F00 + i;
            ms_beacon_t b = { .cost_q8 = cost, .parent = parent,
                              .uptime_s = mesh_now_ms() / 1000 };
            /* frames sent to the fake identities are never forwarded */
            mesh_send_frame(MS_T_BEACON, fake, fake, 0, MS_BCAST_ID, hop,
                            &b, sizeof(b));
            vTaskDelay(pdMS_TO_TICKS(CONFIG_MS_BEACON_MS / CONFIG_MS_ATTACK_N_SYBIL));
        }
    }
}
#endif

void attack_hooks(mesh_hooks_t *hooks, mesh_config_t *cfg)
{
    memset(hooks, 0, sizeof(*hooks));
#if CONFIG_MS_ATTACK_SELFWD
    hooks->drop_forward = drop_selective;
#elif CONFIG_MS_ATTACK_SINKHOLE
    hooks->drop_forward = drop_all;
    hooks->beacon_override = claim_hop1;
#elif CONFIG_MS_ATTACK_REPLAY
    hooks->on_raw_rx = record;
    cfg->passive = true;                  /* outsider: not a mesh member */
#endif
    (void)cfg;
}

void attack_start(void)
{
    ESP_LOGW(TAG, "TESTBED ATTACKER: onset at t=%d s", CONFIG_MS_ATTACK_START_S);
#if CONFIG_MS_ATTACK_REPLAY
    xTaskCreate(replay_task, "replay", 4096, NULL, 4, NULL);
#elif CONFIG_MS_ATTACK_FLOOD
    xTaskCreate(flood_task, "flood", 4096, NULL, 4, NULL);
#elif CONFIG_MS_ATTACK_SYBIL
    xTaskCreate(sybil_task, "sybil", 4096, NULL, 4, NULL);
#endif
}

#else /* !CONFIG_MS_ROLE_ATTACKER */

void attack_hooks(mesh_hooks_t *hooks, mesh_config_t *cfg)
{
    (void)cfg;
    memset(hooks, 0, sizeof(*hooks));
}

void attack_start(void)
{
}

#endif
