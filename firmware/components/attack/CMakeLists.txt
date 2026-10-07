idf_component_register(
    SRCS "attack.c"
    INCLUDE_DIRS "include"
    REQUIRES mesh
    PRIV_REQUIRES esp_timer
)
