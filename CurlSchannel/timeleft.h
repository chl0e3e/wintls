#ifndef __TIMELEFT_H_
#define __TIMELEFT_H_
#include <time.h>
#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define timediff_t clock_t
/* generic function that returns how much time there's left to run, according
   to the timeouts set */
timediff_t Curl_timeleft(struct wintls* data,
    struct curltime* nowp,
    BOOL duringconnect);


struct curltime {
    time_t tv_sec; /* seconds */
    int tv_usec;   /* microseconds */
};

#define DEFAULT_CONNECT_TIMEOUT 300000 /* milliseconds == five minutes */

#define CURL_FORMAT_TIMEDIFF_T CURL_FORMAT_CURL_OFF_T

#define TIMEDIFF_T_MAX CURL_OFF_T_MAX
#define TIMEDIFF_T_MIN CURL_OFF_T_MIN

/*
 * Converts number of milliseconds into a timeval structure.
 *
 * Return values:
 *    NULL IF tv is NULL or ms < 0 (eg. no timeout -> blocking select)
 *    tv with 0 in both fields IF ms == 0 (eg. 0ms timeout -> polling select)
 *    tv with converted fields IF ms > 0 (eg. >0ms timeout -> waiting select)
 */
struct timeval* curlx_mstotv(struct timeval* tv, timediff_t ms);

/*
 * Converts a timeval structure into number of milliseconds.
 */
timediff_t curlx_tvtoms(struct timeval* tv);
struct curltime Curl_now(void);

/*
 * Make sure that the first argument (t1) is the more recent time and t2 is
 * the older time, as otherwise you get a weird negative time-diff back...
 *
 * Returns: the time difference in number of milliseconds.
 */
timediff_t Curl_timediff(struct curltime t1, struct curltime t2);

/*
 * Make sure that the first argument (t1) is the more recent time and t2 is
 * the older time, as otherwise you get a weird negative time-diff back...
 *
 * Returns: the time difference in number of microseconds.
 */
timediff_t Curl_timediff_us(struct curltime newer, struct curltime older);
#ifdef __cplusplus
}
#endif
#endif