#ifndef __DEBUG_H
#define __DEBUG_H

#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <stdio.h>
#include <limits.h>

//#ifdef DEBUGBUILD
//#define DEBUGF(x) x
//#else
//#define DEBUGF(x) do { } while(0)
//#endif

#define DEBUGF(x) x

#if defined(DEBUGBUILD)
#define DEBUGASSERT(x) assert(x)
#else
#define DEBUGASSERT(x) do { } while(0)
#endif

void Curl_infof(struct Curl_easy*, const char* fmt, ...);
void Curl_failf(struct Curl_easy*, const char* fmt, ...);

#define infof Curl_infof
#define failf Curl_failf
/*
 * Macro used to include assertion code only in debug builds.
 */

#undef DEBUGASSERT
#if defined(DEBUGBUILD)
#define DEBUGASSERT(x) assert(x)
#else
#define DEBUGASSERT(x) do { } while(0)
#endif


 /*
  * Macro SOCKERRNO / SET_SOCKERRNO() returns / sets the *socket-related* errno
  * (or equivalent) on this platform to hide platform details to code using it.
  */

#define SOCKERRNO         ((int)WSAGetLastError())
#define SET_SOCKERRNO(x)  (WSASetLastError((int)(x)))

#undef  EBADF            /* override definition in errno.h */
#define EBADF            WSAEBADF
#undef  EINTR            /* override definition in errno.h */
#define EINTR            WSAEINTR
#undef  EINVAL           /* override definition in errno.h */
#define EINVAL           WSAEINVAL
#undef  EWOULDBLOCK      /* override definition in errno.h */
#define EWOULDBLOCK      WSAEWOULDBLOCK
#undef  EINPROGRESS      /* override definition in errno.h */
#define EINPROGRESS      WSAEINPROGRESS
#undef  EALREADY         /* override definition in errno.h */
#define EALREADY         WSAEALREADY
#undef  ENOTSOCK         /* override definition in errno.h */
#define ENOTSOCK         WSAENOTSOCK
#undef  EDESTADDRREQ     /* override definition in errno.h */
#define EDESTADDRREQ     WSAEDESTADDRREQ
#undef  EMSGSIZE         /* override definition in errno.h */
#define EMSGSIZE         WSAEMSGSIZE
#undef  EPROTOTYPE       /* override definition in errno.h */
#define EPROTOTYPE       WSAEPROTOTYPE
#undef  ENOPROTOOPT      /* override definition in errno.h */
#define ENOPROTOOPT      WSAENOPROTOOPT
#undef  EPROTONOSUPPORT  /* override definition in errno.h */
#define EPROTONOSUPPORT  WSAEPROTONOSUPPORT
#define ESOCKTNOSUPPORT  WSAESOCKTNOSUPPORT
#undef  EOPNOTSUPP       /* override definition in errno.h */
#define EOPNOTSUPP       WSAEOPNOTSUPP
#define EPFNOSUPPORT     WSAEPFNOSUPPORT
#undef  EAFNOSUPPORT     /* override definition in errno.h */
#define EAFNOSUPPORT     WSAEAFNOSUPPORT
#undef  EADDRINUSE       /* override definition in errno.h */
#define EADDRINUSE       WSAEADDRINUSE
#undef  EADDRNOTAVAIL    /* override definition in errno.h */
#define EADDRNOTAVAIL    WSAEADDRNOTAVAIL
#undef  ENETDOWN         /* override definition in errno.h */
#define ENETDOWN         WSAENETDOWN
#undef  ENETUNREACH      /* override definition in errno.h */
#define ENETUNREACH      WSAENETUNREACH
#undef  ENETRESET        /* override definition in errno.h */
#define ENETRESET        WSAENETRESET
#undef  ECONNABORTED     /* override definition in errno.h */
#define ECONNABORTED     WSAECONNABORTED
#undef  ECONNRESET       /* override definition in errno.h */
#define ECONNRESET       WSAECONNRESET
#undef  ENOBUFS          /* override definition in errno.h */
#define ENOBUFS          WSAENOBUFS
#undef  EISCONN          /* override definition in errno.h */
#define EISCONN          WSAEISCONN
#undef  ENOTCONN         /* override definition in errno.h */
#define ENOTCONN         WSAENOTCONN
#define ESHUTDOWN        WSAESHUTDOWN
#define ETOOMANYREFS     WSAETOOMANYREFS
#undef  ETIMEDOUT        /* override definition in errno.h */
#define ETIMEDOUT        WSAETIMEDOUT
#undef  ECONNREFUSED     /* override definition in errno.h */
#define ECONNREFUSED     WSAECONNREFUSED
#undef  ELOOP            /* override definition in errno.h */
#define ELOOP            WSAELOOP
#ifndef ENAMETOOLONG     /* possible previous definition in errno.h */
#define ENAMETOOLONG     WSAENAMETOOLONG
#endif
#define EHOSTDOWN        WSAEHOSTDOWN
#undef  EHOSTUNREACH     /* override definition in errno.h */
#define EHOSTUNREACH     WSAEHOSTUNREACH
#ifndef ENOTEMPTY        /* possible previous definition in errno.h */
#define ENOTEMPTY        WSAENOTEMPTY
#endif
#define EPROCLIM         WSAEPROCLIM
#define EUSERS           WSAEUSERS
#define EDQUOT           WSAEDQUOT
#define ESTALE           WSAESTALE
#define EREMOTE          WSAEREMOTE

#endif