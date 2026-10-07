/*
 * Frame authentication (truncated HMAC-SHA256) and control-plane signatures
 * (ECDSA-P256) through the PSA Crypto API of mbedTLS 4 / TF-PSA-Crypto.
 * On the ESP32-S3 SHA-256 runs on the SHA accelerator; ECDSA uses the RSA/MPI
 * accelerator for big-number arithmetic.
 */
#include "sdkconfig.h"
#include "psa/crypto.h"
#include "esp_log.h"
#include "mesh.h"
#include "mesh_keys.h"

static const char *TAG = "mesh_auth";

#define TAG_ALG  PSA_ALG_TRUNCATED_MAC(PSA_ALG_HMAC(PSA_ALG_SHA_256), MS_TAG_LEN)
#define SIG_ALG  PSA_ALG_ECDSA(PSA_ALG_SHA_256)

static psa_key_id_t s_net_key;
static psa_key_id_t s_sink_pub;
#ifdef CONFIG_MS_ROLE_SINK
static psa_key_id_t s_sink_priv;
#endif

esp_err_t mesh_auth_init(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        return ESP_FAIL;
    }
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&a, 256);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&a, TAG_ALG);
    if (psa_import_key(&a, MS_NET_KEY, sizeof(MS_NET_KEY), &s_net_key) != PSA_SUCCESS) {
        ESP_LOGE(TAG, "network key import failed");
        return ESP_FAIL;
    }

    psa_key_attributes_t p = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&p, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&p, 256);
    psa_set_key_usage_flags(&p, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&p, SIG_ALG);
    if (psa_import_key(&p, MS_SINK_PUB, sizeof(MS_SINK_PUB), &s_sink_pub) != PSA_SUCCESS) {
        ESP_LOGE(TAG, "sink public key import failed");
        return ESP_FAIL;
    }

#ifdef CONFIG_MS_ROLE_SINK
    psa_key_attributes_t k = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&k, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&k, 256);
    psa_set_key_usage_flags(&k, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&k, SIG_ALG);
    if (psa_import_key(&k, MS_SINK_PRIV, sizeof(MS_SINK_PRIV), &s_sink_priv) != PSA_SUCCESS) {
        ESP_LOGE(TAG, "sink private key import failed");
        return ESP_FAIL;
    }
#endif
    return ESP_OK;
}

esp_err_t mesh_auth_tag(const uint8_t *msg, size_t len, uint8_t tag[MS_TAG_LEN])
{
    size_t out = 0;
    psa_status_t st = psa_mac_compute(s_net_key, TAG_ALG, msg, len, tag,
                                      MS_TAG_LEN, &out);
    return (st == PSA_SUCCESS && out == MS_TAG_LEN) ? ESP_OK : ESP_FAIL;
}

bool mesh_auth_verify(const uint8_t *msg, size_t len, const uint8_t tag[MS_TAG_LEN])
{
    /* constant-time comparison inside psa_mac_verify */
    return psa_mac_verify(s_net_key, TAG_ALG, msg, len, tag, MS_TAG_LEN) == PSA_SUCCESS;
}

esp_err_t mesh_ctl_sign(const uint8_t *msg, size_t len, uint8_t sig[MS_SIG_LEN])
{
#ifdef CONFIG_MS_ROLE_SINK
    size_t out = 0;
    psa_status_t st = psa_sign_message(s_sink_priv, SIG_ALG, msg, len, sig,
                                       MS_SIG_LEN, &out);
    return (st == PSA_SUCCESS && out == MS_SIG_LEN) ? ESP_OK : ESP_FAIL;
#else
    (void)msg; (void)len; (void)sig;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

bool mesh_ctl_verify(const uint8_t *msg, size_t len, const uint8_t sig[MS_SIG_LEN])
{
    return psa_verify_message(s_sink_pub, SIG_ALG, msg, len, sig, MS_SIG_LEN) == PSA_SUCCESS;
}
