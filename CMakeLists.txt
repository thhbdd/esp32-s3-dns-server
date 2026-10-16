# ESP32-S3 (N16R8) high performance DNS filter / resolver.
#   idf.py set-target esp32s3 && idf.py build flash monitor
cmake_minimum_required(VERSION 3.16)
set(PROJECT_VER "1.0.4")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32s3_dns)

# The device resolves its own names (subscriptions, NTP, DoT/DoH hosts) with
# the configured bootstrap servers: DHCP must not replace them (a router that
# hands out this device as DNS server would make it ask itself).
idf_component_get_property(lwip_lib lwip COMPONENT_LIB)
target_compile_definitions(${lwip_lib} PRIVATE LWIP_DHCP_MAX_DNS_SERVERS=0)
