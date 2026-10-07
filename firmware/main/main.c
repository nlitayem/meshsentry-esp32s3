/*
 * MeshSentry firmware entry point. The role (sink / node / attacker) and the
 * IDS parameters are selected with `idf.py menuconfig`.
 */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#include "mesh.h"
#include "attack.h"

static const char *TAG = "main";

static uint16_t node_id(void)
{
#if CONFIG_MS_ROLE_SINK
    return MS_SINK_ID;
#else
    if (CONFIG_MS_NODE_ID != 0) {
        return CONFIG_MS_NODE_ID;
    }
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    uint16_t id = ((mac[4] << 8) | mac[5]) & 0x7FFF;
    return id ? id : 1;               /* 0 is the sink, 0xFFFF broadcast */
#endif
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    mesh_config_t cfg = { .node_id = node_id() };
    mesh_hooks_t hooks;
    attack_hooks(&hooks, &cfg);
    ESP_ERROR_CHECK(mesh_start(&cfg, &hooks));
    attack_start();
    ESP_LOGI(TAG, "MeshSentry running as node %u", cfg.node_id);
}
