idf_component_register(
    SRCS "ids_monitor.c" "ids_detect.c" "ids_fusion.c"
    INCLUDE_DIRS "include"
    REQUIRES proto
)
