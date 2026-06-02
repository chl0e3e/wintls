# wintls - a single-file Windows Schannel TLS library + example client.
cmake_minimum_required (VERSION 3.8)

project ("wintls" C)

# The TLS library: one translation unit, public header is wintls.h.
add_library (wintls STATIC "wintls.c")
target_include_directories (wintls PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

list(APPEND WINTLS_LIBS bcrypt ncrypt crypt32 secur32 ws2_32)
target_link_libraries(wintls PUBLIC ${WINTLS_LIBS})

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET wintls PROPERTY C_STANDARD 11)
endif()

# Example client that uses only the public API.
add_executable (wintls_example "example.c")
target_link_libraries (wintls_example PRIVATE wintls)
