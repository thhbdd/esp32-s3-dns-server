# AdGuard compatible filter engine (compiler + matcher), shared with the host tools.
file(GLOB FL_SRCS "${CMAKE_CURRENT_LIST_DIR}/src/*.c")
idf_component_register(SRCS ${FL_SRCS}
                       INCLUDE_DIRS "include"
                       PRIV_INCLUDE_DIRS "src"
                       REQUIRES dc_base)
# the matcher is on the query path: optimize for speed even in -Os builds
target_compile_options(${COMPONENT_LIB} PRIVATE -O2)
