

/*
 * Curl_timeleft() returns the amount of milliseconds left allowed for the
 * transfer/connection. If the value is 0, there's no timeout (ie there's
 * infinite time left). If the value is negative, the timeout time has already
 * elapsed.
 *
 * If 'nowp' is non-NULL, it points to the current time.
 * 'duringconnect' is FALSE if not during a connect, as then of course the
 * connect timeout is not taken into account!
 *
 * @unittest: 1303
 */
#include <limits.h>
#define TIMEOUT_CONNECT 1
#define TIMEOUT_MAXTIME 2
#include "wintls.h"

#include "timeleft.h"
#include <time.h>

struct timeval* curlx_mstotv(struct timeval* tv, timediff_t ms)
{
    if (!tv)
        return NULL;

    if (ms < 0)
        return NULL;

    if (ms > 0) {
        timediff_t tv_sec = ms / 1000;
        timediff_t tv_usec = (ms % 1000) * 1000; /* max=999999 */
#ifdef HAVE_SUSECONDS_T
#if TIMEDIFF_T_MAX > TIME_T_MAX
        /* tv_sec overflow check in case time_t is signed */
        if (tv_sec > TIME_T_MAX)
            tv_sec = TIME_T_MAX;
#endif
        tv->tv_sec = (time_t)tv_sec;
        tv->tv_usec = (suseconds_t)tv_usec;
#elif defined(WIN32) /* maybe also others in the future */
#if TIMEDIFF_T_MAX > LONG_MAX
        /* tv_sec overflow check on Windows there we know it is long */
        if (tv_sec > LONG_MAX)
            tv_sec = LONG_MAX;
#endif
        tv->tv_sec = (long)tv_sec;
        tv->tv_usec = (long)tv_usec;
#else
#if TIMEDIFF_T_MAX > INT_MAX
        /* tv_sec overflow check in case time_t is signed */
        if (tv_sec > INT_MAX)
            tv_sec = INT_MAX;
#endif
        tv->tv_sec = (int)tv_sec;
        tv->tv_usec = (int)tv_usec;
#endif
    }
    else {
        tv->tv_sec = 0;
        tv->tv_usec = 0;
    }

    return tv;
}

/*
 * Converts a timeval structure into number of milliseconds.
 */
timediff_t curlx_tvtoms(struct timeval* tv)
{
    return (tv->tv_sec * 1000) + (timediff_t)(((double)tv->tv_usec) / 1000.0);
}


timediff_t Curl_timeleft(struct wintls* tls,
    struct curltime* nowp,
    BOOL duringconnect)
{
    unsigned int timeout_set = 0;
    timediff_t connect_timeout_ms = 0;
    timediff_t maxtime_timeout_ms = 0;
    timediff_t timeout_ms = 0;
    struct curltime now;

    /* The duration of a connect and the total transfer are calculated from two
       different time-stamps. It can end up with the total timeout being reached
       before the connect timeout expires and we must acknowledge whichever
       timeout that is reached first. The total timeout is set per entire
       operation, while the connect timeout is set per connect. */

    if (tls->timeout > 0) {
        timeout_set = TIMEOUT_MAXTIME;
        maxtime_timeout_ms = tls->timeout;
    }
    if (duringconnect) {
        timeout_set |= TIMEOUT_CONNECT;
        connect_timeout_ms = (tls->connecttimeout > 0) ?
            tls->connecttimeout : DEFAULT_CONNECT_TIMEOUT;
    }
    if (!timeout_set)
        /* no timeout  */
        return 0;

    if (!nowp) {
        now = Curl_now();
        nowp = &now;
    }

    if (timeout_set & TIMEOUT_MAXTIME) {
        maxtime_timeout_ms -= Curl_timediff(*nowp, tls->t_startop);
        timeout_ms = maxtime_timeout_ms;
    }

    if (timeout_set & TIMEOUT_CONNECT) {
        connect_timeout_ms -= Curl_timediff(*nowp, tls->t_startsingle);

        if (!(timeout_set & TIMEOUT_MAXTIME) ||
            (connect_timeout_ms < maxtime_timeout_ms))
            timeout_ms = connect_timeout_ms;
    }

    if (!timeout_ms)
        /* avoid returning 0 as that means no timeout! */
        return -1;

    return timeout_ms;
}

/* set in win32_init() */
extern LARGE_INTEGER Curl_freq;
extern BOOL Curl_isVistaOrGreater;
timediff_t Curl_timediff(struct curltime newer, struct curltime older)
{
    timediff_t diff = (timediff_t)newer.tv_sec - older.tv_sec;
    if (diff >= (LONG_MAX / 1000))
        return LONG_MAX;
    else if (diff <= (LONG_MIN / 1000))
        return LONG_MIN;
    return diff * 1000 + (newer.tv_usec - older.tv_usec) / 1000;
}

/* In case of bug fix this function has a counterpart in tool_util.c */
struct curltime Curl_now(void)
{
    struct curltime now;
    if (Curl_isVistaOrGreater) { /* QPC timer might have issues pre-Vista */
        LARGE_INTEGER count;
        QueryPerformanceCounter(&count);
        now.tv_sec = (time_t)(count.QuadPart / Curl_freq.QuadPart);
        now.tv_usec = (int)((count.QuadPart % Curl_freq.QuadPart) * 1000000 /
            Curl_freq.QuadPart);
    }
    else {
        /* Disable /analyze warning that GetTickCount64 is preferred  */
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:28159)
#endif
        DWORD milliseconds = GetTickCount();
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

        now.tv_sec = milliseconds / 1000;
        now.tv_usec = (milliseconds % 1000) * 1000;
    }
    return now;
}