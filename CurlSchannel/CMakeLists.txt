# CMakeList.txt : CMake project for CurlSchannel, include source and define
# project specific logic here.
#
# Add source to this project's executable.
add_executable (CurlSchannel "schannel_curl.c" "CurlSchannel.cpp" "CurlSchannel.h" "schannel_curl.c" "curl_sspi.c" "curl_sspi.h" "schannel_curl.h" "schannel_verify.c"  "schannel_verify.h" "curlcode.h" "version_win32.c" "version_win32.h" "strerror.h" "strerror.c" "schannel_verify.c" "x509asn1.c" "wintls.h" "dynbuf.h" "dynbuf.c" "alpn.c" "alpn.h" "timeleft.h" "timeleft.c" "schannel_verify.h" "select.c" "select.h" "msvc.h" "debug.h" "wintls.c" "strcase.h" "strcase.c" "curl_multibyte.h" "curl_multibyte.c" "base64.h" "base64.c" "hostcheck.h" "hostcheck.c" "system_win32.h" "system_win32.c" "curl_printf.c" "curl_printf.h" "memrchr.c" "memrchr.h" "debug.c" "charhelper.h" "slist.h" "slist.c" "curl_opts.h")
add_compile_definitions(WITH_SCHANNEL)
list(APPEND LIBRARIES bcrypt ncrypt crypt32 secur32)
set(CMAKE_REQUIRED_LIBRARIES ${LIBRARIES})

target_compile_options(CurlSchannel PRIVATE /analyze)
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET CurlSchannel PROPERTY CXX_STANDARD 20)
endif()
target_link_libraries(CurlSchannel PRIVATE ${LIBRARIES})
