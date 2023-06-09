#include "debug.h"
#include "wintls.h"
#include "curl_printf.h"


#define MAXINFO 2048
#define CURL_ERROR_SIZE 256

void Curl_debug(struct wintls* data, curl_infotype type,
    char* ptr, size_t size)
{
    static const char s_infotype[CURLINFO_END][3] = {
             "* ", "< ", "> ", "{ ", "} ", "{ ", "} " };
    printf(s_infotype[type]);
    printf(ptr);
}

void Curl_infof(struct wintls* data, const char* fmt, ...)
{
    DEBUGASSERT(!strchr(fmt, '\n'));
    if (data) { //&& data->set.verbose) {
        va_list ap;
        int len;
        char buffer[MAXINFO + 2];
        va_start(ap, fmt);
        len = mvsnprintf(buffer, MAXINFO, fmt, ap);
        va_end(ap);
        buffer[len++] = '\n';
        buffer[len] = '\0';
        Curl_debug(data, CURLINFO_TEXT, buffer, len);
    }
}

/* Curl_failf() is for messages stating why we failed.
 * The message SHALL NOT include any LF or CR.
 */
void Curl_failf(struct wintls* data, const char* fmt, ...)
{
    DEBUGASSERT(!strchr(fmt, '\n'));
    if (data) {
        va_list ap;
        int len;
        char error[CURL_ERROR_SIZE + 2];
        va_start(ap, fmt);
        len = mvsnprintf(error, CURL_ERROR_SIZE, fmt, ap);

        error[len++] = '\n';
        error[len] = '\0';
        Curl_debug(data, CURLINFO_TEXT, error, len);
        va_end(ap);
    }
}