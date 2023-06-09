#ifndef HEADER_CURL_VERSION_WIN32_H
#define HEADER_CURL_VERSION_WIN32_H

#define CURLX_FUNCTION_CAST(target_type, func) \
  (target_type)(void (*) (void))(func)

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
/* Version condition */
typedef enum {
    VERSION_LESS_THAN,
    VERSION_LESS_THAN_EQUAL,
    VERSION_EQUAL,
    VERSION_GREATER_THAN_EQUAL,
    VERSION_GREATER_THAN
} VersionCondition;

/* Platform identifier */
typedef enum {
    PLATFORM_DONT_CARE,
    PLATFORM_WINDOWS,
    PLATFORM_WINNT
} PlatformIdentifier;

/* This is used to verify if we are running on a specific windows version */
BOOL curlx_verify_windows_version(const unsigned int majorVersion,
    const unsigned int minorVersion,
    const unsigned int buildVersion,
    const PlatformIdentifier platform,
    const VersionCondition condition);

#endif /* HEADER_CURL_VERSION_WIN32_H */
