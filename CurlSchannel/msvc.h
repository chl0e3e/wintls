#ifndef _SSIZE_T_DEFINED
#  if defined(__POCC__) || defined(__MINGW32__)
#  elif defined(_WIN64)
#    define _SSIZE_T_DEFINED
#    define ssize_t __int64
#  else
#    define _SSIZE_T_DEFINED
#    define ssize_t int
#  endif
#endif

#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SIZE_T size_t;
#endif

#define Curl_safefree(ptr) \
  do { free((ptr)); (ptr) = NULL;} while(0)
