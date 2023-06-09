#ifndef HEADER_CURL_HOSTCHECK_H
#define HEADER_CURL_HOSTCHECK_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/


#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include "curlcode.h"
#include "debug.h"
#include <ws2tcpip.h>

 /* returns TRUE if there's a match */
BOOL Curl_cert_hostcheck(const char* match_pattern, size_t matchlen,
    const char* hostname, size_t hostlen);

#endif /* HEADER_CURL_HOSTCHECK_H */
