#include "strerror.h"
#include "curl_printf.h"


#if defined(WIN32) || defined(_WIN32_WCE)
/* This is a helper function for Curl_strerror that converts Windows API error
 * codes (GetLastError) to error messages.
 * Returns NULL if no error message was found for error code.
 */
static const char*
get_winapi_error(int err, char* buf, size_t buflen)
{
    char* p;
    wchar_t wbuf[256];

    if (!buflen)
        return NULL;

    *buf = '\0';
    *wbuf = L'\0';

    /* We return the local codepage version of the error string because if it is
       output to the user's terminal it will likely be with functions which
       expect the local codepage (eg fprintf, failf, infof).
       FormatMessageW -> wcstombs is used for Windows CE compatibility. */
    if (FormatMessageW((FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS), NULL, err,
        LANG_NEUTRAL, wbuf, sizeof(wbuf) / sizeof(wchar_t), NULL)) {
        size_t written = wcstombs(buf, wbuf, buflen - 1);
        if (written != (size_t)-1)
            buf[written] = '\0';
        else
            *buf = '\0';
    }

    /* Truncate multiple lines */
    p = strchr(buf, '\n');
    if (p) {
        if (p > buf && *(p - 1) == '\r')
            *(p - 1) = '\0';
        else
            *p = '\0';
    }

    return (*buf ? buf : NULL);
}
#endif /* WIN32 || _WIN32_WCE */


/*
 * Curl_winapi_strerror:
 * Variant of Curl_strerror if the error code is definitely Windows API.
 */
#if defined(WIN32) || defined(_WIN32_WCE)
const char* Curl_winapi_strerror(DWORD err, char* buf, size_t buflen)
{
#ifdef PRESERVE_WINDOWS_ERROR_CODE
    DWORD old_win_err = GetLastError();
#endif
    int old_errno = errno;

    if (!buflen)
        return NULL;

    *buf = '\0';

#ifndef CURL_DISABLE_VERBOSE_STRINGS
    if (!get_winapi_error(err, buf, buflen)) {
        msnprintf(buf, buflen, "Unknown error %u (0x%08X)", err, err);
    }
#else
    {
        const char* txt = (err == ERROR_SUCCESS) ? "No error" : "Error";
        strncpy(buf, txt, buflen);
        buf[buflen - 1] = '\0';
    }
#endif

    if (errno != old_errno)
        errno = old_errno;

#ifdef PRESERVE_WINDOWS_ERROR_CODE
    if (old_win_err != GetLastError())
        SetLastError(old_win_err);
#endif

    return buf;
}
#endif /* WIN32 || _WIN32_WCE */

/*
 * Curl_sspi_strerror:
 * Variant of Curl_strerror if the error code is definitely Windows SSPI.
 */
const char* Curl_sspi_strerror(int err, char* buf, size_t buflen)
{
#ifdef PRESERVE_WINDOWS_ERROR_CODE
    DWORD old_win_err = GetLastError();
#endif
    int old_errno = errno;
    const char* txt;

    if (!buflen)
        return NULL;

    *buf = '\0';

#ifndef CURL_DISABLE_VERBOSE_STRINGS

    switch (err) {
    case SEC_E_OK:
        txt = "No error";
        break;
#define SEC2TXT(sec) case sec: txt = #sec; break
        SEC2TXT(CRYPT_E_REVOKED);
        SEC2TXT(SEC_E_ALGORITHM_MISMATCH);
        SEC2TXT(SEC_E_BAD_BINDINGS);
        SEC2TXT(SEC_E_BAD_PKGID);
        SEC2TXT(SEC_E_BUFFER_TOO_SMALL);
        SEC2TXT(SEC_E_CANNOT_INSTALL);
        SEC2TXT(SEC_E_CANNOT_PACK);
        SEC2TXT(SEC_E_CERT_EXPIRED);
        SEC2TXT(SEC_E_CERT_UNKNOWN);
        SEC2TXT(SEC_E_CERT_WRONG_USAGE);
        SEC2TXT(SEC_E_CONTEXT_EXPIRED);
        SEC2TXT(SEC_E_CROSSREALM_DELEGATION_FAILURE);
        SEC2TXT(SEC_E_CRYPTO_SYSTEM_INVALID);
        SEC2TXT(SEC_E_DECRYPT_FAILURE);
        SEC2TXT(SEC_E_DELEGATION_POLICY);
        SEC2TXT(SEC_E_DELEGATION_REQUIRED);
        SEC2TXT(SEC_E_DOWNGRADE_DETECTED);
        SEC2TXT(SEC_E_ENCRYPT_FAILURE);
        SEC2TXT(SEC_E_ILLEGAL_MESSAGE);
        SEC2TXT(SEC_E_INCOMPLETE_CREDENTIALS);
        SEC2TXT(SEC_E_INCOMPLETE_MESSAGE);
        SEC2TXT(SEC_E_INSUFFICIENT_MEMORY);
        SEC2TXT(SEC_E_INTERNAL_ERROR);
        SEC2TXT(SEC_E_INVALID_HANDLE);
        SEC2TXT(SEC_E_INVALID_PARAMETER);
        SEC2TXT(SEC_E_INVALID_TOKEN);
        SEC2TXT(SEC_E_ISSUING_CA_UNTRUSTED);
        SEC2TXT(SEC_E_ISSUING_CA_UNTRUSTED_KDC);
        SEC2TXT(SEC_E_KDC_CERT_EXPIRED);
        SEC2TXT(SEC_E_KDC_CERT_REVOKED);
        SEC2TXT(SEC_E_KDC_INVALID_REQUEST);
        SEC2TXT(SEC_E_KDC_UNABLE_TO_REFER);
        SEC2TXT(SEC_E_KDC_UNKNOWN_ETYPE);
        SEC2TXT(SEC_E_LOGON_DENIED);
        SEC2TXT(SEC_E_MAX_REFERRALS_EXCEEDED);
        SEC2TXT(SEC_E_MESSAGE_ALTERED);
        SEC2TXT(SEC_E_MULTIPLE_ACCOUNTS);
        SEC2TXT(SEC_E_MUST_BE_KDC);
        SEC2TXT(SEC_E_NOT_OWNER);
        SEC2TXT(SEC_E_NO_AUTHENTICATING_AUTHORITY);
        SEC2TXT(SEC_E_NO_CREDENTIALS);
        SEC2TXT(SEC_E_NO_IMPERSONATION);
        SEC2TXT(SEC_E_NO_IP_ADDRESSES);
        SEC2TXT(SEC_E_NO_KERB_KEY);
        SEC2TXT(SEC_E_NO_PA_DATA);
        SEC2TXT(SEC_E_NO_S4U_PROT_SUPPORT);
        SEC2TXT(SEC_E_NO_TGT_REPLY);
        SEC2TXT(SEC_E_OUT_OF_SEQUENCE);
        SEC2TXT(SEC_E_PKINIT_CLIENT_FAILURE);
        SEC2TXT(SEC_E_PKINIT_NAME_MISMATCH);
        SEC2TXT(SEC_E_POLICY_NLTM_ONLY);
        SEC2TXT(SEC_E_QOP_NOT_SUPPORTED);
        SEC2TXT(SEC_E_REVOCATION_OFFLINE_C);
        SEC2TXT(SEC_E_REVOCATION_OFFLINE_KDC);
        SEC2TXT(SEC_E_SECPKG_NOT_FOUND);
        SEC2TXT(SEC_E_SECURITY_QOS_FAILED);
        SEC2TXT(SEC_E_SHUTDOWN_IN_PROGRESS);
        SEC2TXT(SEC_E_SMARTCARD_CERT_EXPIRED);
        SEC2TXT(SEC_E_SMARTCARD_CERT_REVOKED);
        SEC2TXT(SEC_E_SMARTCARD_LOGON_REQUIRED);
        SEC2TXT(SEC_E_STRONG_CRYPTO_NOT_SUPPORTED);
        SEC2TXT(SEC_E_TARGET_UNKNOWN);
        SEC2TXT(SEC_E_TIME_SKEW);
        SEC2TXT(SEC_E_TOO_MANY_PRINCIPALS);
        SEC2TXT(SEC_E_UNFINISHED_CONTEXT_DELETED);
        SEC2TXT(SEC_E_UNKNOWN_CREDENTIALS);
        SEC2TXT(SEC_E_UNSUPPORTED_FUNCTION);
        SEC2TXT(SEC_E_UNSUPPORTED_PREAUTH);
        SEC2TXT(SEC_E_UNTRUSTED_ROOT);
        SEC2TXT(SEC_E_WRONG_CREDENTIAL_HANDLE);
        SEC2TXT(SEC_E_WRONG_PRINCIPAL);
        SEC2TXT(SEC_I_COMPLETE_AND_CONTINUE);
        SEC2TXT(SEC_I_COMPLETE_NEEDED);
        SEC2TXT(SEC_I_CONTEXT_EXPIRED);
        SEC2TXT(SEC_I_CONTINUE_NEEDED);
        SEC2TXT(SEC_I_INCOMPLETE_CREDENTIALS);
        SEC2TXT(SEC_I_LOCAL_LOGON);
        SEC2TXT(SEC_I_NO_LSA_CONTEXT);
        SEC2TXT(SEC_I_RENEGOTIATE);
        SEC2TXT(SEC_I_SIGNATURE_NEEDED);
    default:
        txt = "Unknown error";
    }

    if (err == SEC_E_ILLEGAL_MESSAGE) {
        msnprintf(buf, buflen,
            "SEC_E_ILLEGAL_MESSAGE (0x%08X) - This error usually occurs "
            "when a fatal SSL/TLS alert is received (e.g. handshake failed)."
            " More detail may be available in the Windows System event log.",
            err);
    }
    else {
        char txtbuf[80];
        char msgbuf[256];

        msnprintf(txtbuf, sizeof(txtbuf), "%s (0x%08X)", txt, err);

        if (get_winapi_error(err, msgbuf, sizeof(msgbuf)))
            msnprintf(buf, buflen, "%s - %s", txtbuf, msgbuf);
        else {
            strncpy(buf, txtbuf, buflen);
            buf[buflen - 1] = '\0';
        }
    }

#else
    if (err == SEC_E_OK)
        txt = "No error";
    else
        txt = "Error";
    strncpy(buf, txt, buflen);
    buf[buflen - 1] = '\0';
#endif

    if (errno != old_errno)
        errno = old_errno;

#ifdef PRESERVE_WINDOWS_ERROR_CODE
    if (old_win_err != GetLastError())
        SetLastError(old_win_err);
#endif

    return buf;
}