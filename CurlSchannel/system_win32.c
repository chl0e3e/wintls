#include "system_win32.h"
#include "version_win32.h"
#include "curl_sspi.h"

LARGE_INTEGER Curl_freq;
BOOL Curl_isVistaOrGreater;

/* Handle of iphlpapp.dll */
static HMODULE s_hIpHlpApiDll = NULL;

/* Pointer to the if_nametoindex function */
IF_NAMETOINDEX_FN Curl_if_nametoindex = NULL;

/* Curl_win32_init() performs win32 global initialization */
extern CURLcode Curl_win32_init(long flags)
{
    /* CURL_GLOBAL_WIN32 controls the *optional* part of the initialization which
       is just for Winsock at the moment. Any required win32 initialization
       should take place after this block. */
    if (flags & CURL_GLOBAL_WIN32) {
        WORD wVersionRequested;
        WSADATA wsaData;
        int res;

        wVersionRequested = MAKEWORD(2, 2);
        res = WSAStartup(wVersionRequested, &wsaData);

        if (res)
            /* Tell the user that we couldn't find a usable */
            /* winsock.dll.     */
            return CURLE_FAILED_INIT;

        /* Confirm that the Windows Sockets DLL supports what we need.*/
        /* Note that if the DLL supports versions greater */
        /* than wVersionRequested, it will still return */
        /* wVersionRequested in wVersion. wHighVersion contains the */
        /* highest supported version. */

        if (LOBYTE(wsaData.wVersion) != LOBYTE(wVersionRequested) ||
            HIBYTE(wsaData.wVersion) != HIBYTE(wVersionRequested)) {
            /* Tell the user that we couldn't find a usable */

            /* winsock.dll. */
            WSACleanup();
            return CURLE_FAILED_INIT;
        }
    } /* CURL_GLOBAL_WIN32 */

    {
        CURLcode result = Curl_sspi_global_init();
        if (result)
            return result;
    }

    s_hIpHlpApiDll = LoadLibraryA("iphlpapi.dll");
    if (s_hIpHlpApiDll) {
        /* Get the address of the if_nametoindex function */
        IF_NAMETOINDEX_FN pIfNameToIndex =
            CURLX_FUNCTION_CAST(IF_NAMETOINDEX_FN,
                (GetProcAddress(s_hIpHlpApiDll, "if_nametoindex")));

        if (pIfNameToIndex)
            Curl_if_nametoindex = pIfNameToIndex;
    }

    /* curlx_verify_windows_version must be called during init at least once
       because it has its own initialization routine. */
    if (curlx_verify_windows_version(6, 0, 0, PLATFORM_WINNT,
        VERSION_GREATER_THAN_EQUAL)) {
        Curl_isVistaOrGreater = TRUE;
    }
    else
        Curl_isVistaOrGreater = FALSE;

    QueryPerformanceFrequency(&Curl_freq);
    return CURLE_OK;
}

/* Curl_win32_cleanup() is the opposite of Curl_win32_init() */
void Curl_win32_cleanup(long init_flags)
{
    if (s_hIpHlpApiDll) {
        FreeLibrary(s_hIpHlpApiDll);
        s_hIpHlpApiDll = NULL;
        Curl_if_nametoindex = NULL;
    }

    Curl_sspi_global_cleanup();

    if (init_flags & CURL_GLOBAL_WIN32) {
        WSACleanup();
    }
}

#if !defined(LOAD_WITH_ALTERED_SEARCH_PATH)
#define LOAD_WITH_ALTERED_SEARCH_PATH  0x00000008
#endif

#if !defined(LOAD_LIBRARY_SEARCH_SYSTEM32)
#define LOAD_LIBRARY_SEARCH_SYSTEM32   0x00000800
#endif

/* We use our own typedef here since some headers might lack these */
typedef HMODULE(APIENTRY* LOADLIBRARYEX_FN)(LPCTSTR, HANDLE, DWORD);

/* See function definitions in winbase.h */
#ifdef UNICODE
#  ifdef _WIN32_WCE
#    define LOADLIBARYEX  L"LoadLibraryExW"
#  else
#    define LOADLIBARYEX  "LoadLibraryExW"
#  endif
#else
#  define LOADLIBARYEX    "LoadLibraryExA"
#endif

/*
 * Curl_load_library()
 *
 * This is used to dynamically load DLLs using the most secure method available
 * for the version of Windows that we are running on.
 *
 * Parameters:
 *
 * filename  [in] - The filename or full path of the DLL to load. If only the
 *                  filename is passed then the DLL will be loaded from the
 *                  Windows system directory.
 *
 * Returns the handle of the module on success; otherwise NULL.
 */
HMODULE Curl_load_library(LPCTSTR filename)
{
#ifndef CURL_WINDOWS_APP
    HMODULE hModule = NULL;
    LOADLIBRARYEX_FN pLoadLibraryEx = NULL;

    /* Get a handle to kernel32 so we can access it's functions at runtime */
    HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32"));
    if (!hKernel32)
        return NULL;

    /* Attempt to find LoadLibraryEx() which is only available on Windows 2000
       and above */
    pLoadLibraryEx =
        CURLX_FUNCTION_CAST(LOADLIBRARYEX_FN,
            (GetProcAddress(hKernel32, LOADLIBARYEX)));

    /* Detect if there's already a path in the filename and load the library if
       there is. Note: Both back slashes and forward slashes have been supported
       since the earlier days of DOS at an API level although they are not
       supported by command prompt */
    if (strpbrk(filename, TEXT("\\/"))) {
        /** !checksrc! disable BANNEDFUNC 1 **/
        hModule = pLoadLibraryEx ?
            pLoadLibraryEx(filename, NULL, LOAD_WITH_ALTERED_SEARCH_PATH) :
            LoadLibrary(filename);
    }
    /* Detect if KB2533623 is installed, as LOAD_LIBRARY_SEARCH_SYSTEM32 is only
       supported on Windows Vista, Windows Server 2008, Windows 7 and Windows
       Server 2008 R2 with this patch or natively on Windows 8 and above */
    else if (pLoadLibraryEx && GetProcAddress(hKernel32, "AddDllDirectory")) {
        /* Load the DLL from the Windows system directory */
        hModule = pLoadLibraryEx(filename, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    else {
        /* Attempt to get the Windows system path */
        UINT systemdirlen = GetSystemDirectory(NULL, 0);
        if (systemdirlen) {
            /* Allocate space for the full DLL path (Room for the null terminator
               is included in systemdirlen) */
            size_t filenamelen = strlen(filename);
            int n = systemdirlen + 1 + filenamelen;
            char path = (char*)malloc(n * sizeof(char));
            if (path && GetSystemDirectory(path, systemdirlen)) {
                /* Calculate the full DLL path */
                strcpy_s(path + strlen(path), 1, "\\");
                strcpy_s(path + strlen(path), strlen(filename), filename);

                /* Load the DLL from the Windows system directory */
                /** !checksrc! disable BANNEDFUNC 1 **/
                hModule = pLoadLibraryEx ?
                    pLoadLibraryEx(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH) :
                    LoadLibrary(path);

            }
            free(path);
        }
    }
    return hModule;
#else
    /* the Universal Windows Platform (UWP) can't do this */
    (void)filename;
    return NULL;
#endif
}
