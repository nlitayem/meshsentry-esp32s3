# Testbed key material (network HMAC key + sink ECDSA-P256 key pair),
# generated once per checkout by tools/gen_keys.py into keys/ (git-ignored)
# so that every node flashed from this tree shares the same keys.
set(keys_dir "${CMAKE_CURRENT_LIST_DIR}/../../keys")
if(NOT EXISTS "${keys_dir}/mesh_keys.h" AND NOT CMAKE_BUILD_EARLY_EXPANSION)
    execute_process(
        COMMAND ${python} "${CMAKE_CURRENT_LIST_DIR}/../../tools/gen_keys.py"
                "${keys_dir}/mesh_keys.h"
        RESULT_VARIABLE gen_rc)
    if(NOT gen_rc EQUAL 0)
        message(FATAL_ERROR "tools/gen_keys.py failed")
    endif()
endif()
file(MAKE_DIRECTORY "${keys_dir}")

idf_component_register(
    SRCS "mesh.c" "mesh_auth.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "${keys_dir}"
    REQUIRES proto ids esp_wifi esp_timer nvs_flash mbedtls
    PRIV_REQUIRES esp_netif esp_event
)
