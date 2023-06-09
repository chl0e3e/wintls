#include "curl_multibyte.h"


wchar_t* curlx_convert_UTF8_to_wchar(const char* str_utf8)
{
    wchar_t* str_w = NULL;

    if (str_utf8) {
        int str_w_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            str_utf8, -1, NULL, 0);
        if (str_w_len > 0) {
            str_w = malloc(str_w_len * sizeof(wchar_t));
            if (str_w) {
                if (MultiByteToWideChar(CP_UTF8, 0, str_utf8, -1, str_w,
                    str_w_len) == 0) {
                    free(str_w);
                    return NULL;
                }
            }
        }
    }

    return str_w;
}

char* curlx_convert_wchar_to_UTF8(const wchar_t* str_w)
{
    char* str_utf8 = NULL;

    if (str_w) {
        int bytes = WideCharToMultiByte(CP_UTF8, 0, str_w, -1,
            NULL, 0, NULL, NULL);
        if (bytes > 0) {
            str_utf8 = malloc(bytes);
            if (str_utf8) {
                if (WideCharToMultiByte(CP_UTF8, 0, str_w, -1, str_utf8, bytes,
                    NULL, NULL) == 0) {
                    free(str_utf8);
                    return NULL;
                }
            }
        }
    }

    return str_utf8;
}
