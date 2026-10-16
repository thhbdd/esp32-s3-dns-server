idf_component_register(
    SRCS "app_main.c" "app_config.c" "dot_server.c" "net.c" "rules.c" "upstream_tls.c" "web.c"
    INCLUDE_DIRS "."
    REQUIRES dc_base fl_filter dns_core nvs_flash esp_wifi esp_netif esp_event
             esp_http_server esp_https_server esp_http_client esp_https_ota esp-tls mbedtls app_update
             esp_partition spi_flash esp_timer esp_driver_gpio vfs lwip esp_app_format)

# Web UI: gzip-compressed at build time and embedded in the firmware.
idf_build_get_property(python PYTHON)
set(WEB_SRC ${CMAKE_CURRENT_LIST_DIR}/../web/index.html)
set(WEB_GZ ${CMAKE_CURRENT_BINARY_DIR}/index.html.gz)
add_custom_command(
    OUTPUT ${WEB_GZ}
    COMMAND ${python} -c "import gzip,sys; d=open(sys.argv[1],'rb').read(); open(sys.argv[2],'wb').write(gzip.compress(d,9,mtime=0))" ${WEB_SRC} ${WEB_GZ}
    DEPENDS ${WEB_SRC}
    VERBATIM)
add_custom_target(web_ui_gz DEPENDS ${WEB_GZ})
add_dependencies(${COMPONENT_LIB} web_ui_gz)
target_add_binary_data(${COMPONENT_LIB} ${WEB_GZ} BINARY)
