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

#include "hostcheck.h"
#include "strcase.h"
#include "memrchr.h"



 /*
  * Curl_host_is_ipnum() returns TRUE if the given string is a numerical IPv4
  * (or IPv6 if supported) address.
  */
BOOL Curl_host_is_ipnum(const char* hostname)
{
    struct in_addr in;
#ifdef ENABLE_IPV6
    struct in6_addr in6;
#endif
    if (inet_pton(AF_INET, hostname, &in) > 0
#ifdef ENABLE_IPV6
        || Curl_inet_pton(AF_INET6, hostname, &in6) > 0
#endif
        )
        return TRUE;
    return FALSE;
}


/* check the two input strings with given length, but do not
   assume they end in nul-bytes */
static BOOL pmatch(const char* hostname, size_t hostlen,
    const char* pattern, size_t patternlen)
{
    if (hostlen != patternlen)
        return FALSE;
    return strncasecompare(hostname, pattern, hostlen);
}

/*
 * Match a hostname against a wildcard pattern.
 * E.g.
 *  "foo.host.com" matches "*.host.com".
 *
 * We use the matching rule described in RFC6125, section 6.4.3.
 * https://datatracker.ietf.org/doc/html/rfc6125#section-6.4.3
 *
 * In addition: ignore trailing dots in the host names and wildcards, so that
 * the names are used normalized. This is what the browsers do.
 *
 * Do not allow wildcard matching on IP numbers. There are apparently
 * certificates being used with an IP address in the CN field, thus making no
 * apparent distinction between a name and an IP. We need to detect the use of
 * an IP address and not wildcard match on such names.
 *
 * Only match on "*" being used for the leftmost label, not "a*", "a*b" nor
 * "*b".
 *
 * Return TRUE on a match. FALSE if not.
 *
 * @unittest: 1397
 */

static BOOL hostmatch(const char* hostname,
    size_t hostlen,
    const char* pattern,
    size_t patternlen)
{
    const char* pattern_label_end;

    DEBUGASSERT(pattern);
    DEBUGASSERT(patternlen);
    DEBUGASSERT(hostname);
    DEBUGASSERT(hostlen);

    /* normalize pattern and hostname by stripping off trailing dots */
    if (hostname[hostlen - 1] == '.')
        hostlen--;
    if (pattern[patternlen - 1] == '.')
        patternlen--;

    if (strncmp(pattern, "*.", 2))
        return pmatch(hostname, hostlen, pattern, patternlen);

    /* detect IP address as hostname and fail the match if so */
    else if (Curl_host_is_ipnum(hostname))
        return FALSE;

    /* We require at least 2 dots in the pattern to avoid too wide wildcard
       match. */
    pattern_label_end = memchr(pattern, '.', patternlen);
    if (!pattern_label_end ||
        (memrchr(pattern, '.', patternlen) == pattern_label_end))
        return pmatch(hostname, hostlen, pattern, patternlen);
    else {
        const char* hostname_label_end = memchr(hostname, '.', hostlen);
        if (hostname_label_end) {
            size_t skiphost = hostname_label_end - hostname;
            size_t skiplen = pattern_label_end - pattern;
            return pmatch(hostname_label_end, hostlen - skiphost,
                pattern_label_end, patternlen - skiplen);
        }
    }
    return FALSE;
}

/*
 * Curl_cert_hostcheck() returns TRUE if a match and FALSE if not.
 */
BOOL Curl_cert_hostcheck(const char* match, size_t matchlen,
    const char* hostname, size_t hostlen)
{
    if (match && *match && hostname && *hostname)
        return hostmatch(hostname, hostlen, match, matchlen);
    return FALSE;
}
