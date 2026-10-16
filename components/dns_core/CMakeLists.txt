idf_component_register(
    SRCS "src/dns_wire.c" "src/dns_cache.c" "src/dns_local.c" "src/dns_engine.c"
         "src/dns_server.c" "src/dns_stats.c" "src/dns_config.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "src"
    REQUIRES dc_base fl_filter lwip)
# the query path is hot: optimize for speed even in size-optimized builds
target_compile_options(${COMPONENT_LIB} PRIVATE -O2)
