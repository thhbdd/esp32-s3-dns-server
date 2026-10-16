idf_component_register(SRCS "src/dc_util.c" "src/dc_net.c" "src/dc_port_esp.c"
                       INCLUDE_DIRS "include"
                       REQUIRES esp_timer heap log esp_hw_support freertos)
target_compile_options(${COMPONENT_LIB} PRIVATE -O2)
