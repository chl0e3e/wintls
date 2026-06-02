# wintls - single-file Windows Schannel TLS client.
cmake_minimum_required (VERSION 3.8)

project ("wintls" C)

add_executable (wintls "wintls.c")

list(APPEND LIBRARIES bcrypt ncrypt crypt32 secur32 ws2_32)
target_link_libraries(wintls PRIVATE ${LIBRARIES})

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET wintls PROPERTY C_STANDARD 11)
endif()
