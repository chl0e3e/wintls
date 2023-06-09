#ifndef __CURL_OPTS_H
#define __CURL_OPTS_H
enum dupstring {
	STRING_CERT,            /* client certificate file name */
	STRING_CERT_PROXY,      /* client certificate file name */
	STRING_CERT_TYPE,       /* format for certificate (default: PEM)*/
	STRING_CERT_TYPE_PROXY, /* format for certificate (default: PEM)*/
	STRING_COOKIE,          /* HTTP cookie string to send */
	STRING_COOKIEJAR,       /* dump all cookies to this file */
	STRING_CUSTOMREQUEST,   /* HTTP/FTP/RTSP request/method to use */
	STRING_DEFAULT_PROTOCOL, /* Protocol to use when the URL doesn't specify */
	STRING_DEVICE,          /* local network interface/address to use */
	STRING_ENCODING,        /* Accept-Encoding string */
	STRING_FTP_ACCOUNT,     /* ftp account data */
	STRING_FTP_ALTERNATIVE_TO_USER, /* command to send if USER/PASS fails */
	STRING_FTPPORT,         /* port to send with the FTP PORT command */
	STRING_KEY,             /* private key file name */
	STRING_KEY_PROXY,       /* private key file name */
	STRING_KEY_PASSWD,      /* plain text private key password */
	STRING_KEY_PASSWD_PROXY, /* plain text private key password */
	STRING_KEY_TYPE,        /* format for private key (default: PEM) */
	STRING_KEY_TYPE_PROXY,  /* format for private key (default: PEM) */
	STRING_KRB_LEVEL,       /* krb security level */
	STRING_NETRC_FILE,      /* if not NULL, use this instead of trying to find $HOME/.netrc */
	STRING_PROXY,           /* proxy to use */
	STRING_PRE_PROXY,       /* pre socks proxy to use */
	STRING_SET_RANGE,       /* range, if used */
	STRING_SET_REFERER,     /* custom string for the HTTP referer field */
	STRING_SET_URL,         /* what original URL to work on */
	STRING_SSL_CAPATH,      /* CA directory name (doesn't work on windows) */
	STRING_SSL_CAPATH_PROXY, /* CA directory name (doesn't work on windows) */
	STRING_SSL_CAFILE,      /* certificate file to verify peer against */
	STRING_SSL_CAFILE_PROXY, /* certificate file to verify peer against */
	STRING_SSL_PINNEDPUBLICKEY, /* public key file to verify peer against */
	STRING_SSL_PINNEDPUBLICKEY_PROXY, /* public key file to verify proxy */
	STRING_SSL_CIPHER_LIST, /* list of ciphers to use */
	STRING_SSL_CIPHER_LIST_PROXY, /* list of ciphers to use */
	STRING_SSL_CIPHER13_LIST, /* list of TLS 1.3 ciphers to use */
	STRING_SSL_CIPHER13_LIST_PROXY, /* list of TLS 1.3 ciphers to use */
	STRING_USERAGENT,       /* User-Agent string */
	STRING_SSL_CRLFILE,     /* crl file to check certificate */
	STRING_SSL_CRLFILE_PROXY, /* crl file to check certificate */
	STRING_SSL_ISSUERCERT, /* issuer cert file to check certificate */
	STRING_SSL_ISSUERCERT_PROXY, /* issuer cert file to check certificate */
	STRING_SSL_ENGINE,      /* name of ssl engine */
	STRING_USERNAME,        /* <username>, if used */
	STRING_PASSWORD,        /* <password>, if used */
	STRING_OPTIONS,         /* <options>, if used */
	STRING_PROXYUSERNAME,   /* Proxy <username>, if used */
	STRING_PROXYPASSWORD,   /* Proxy <password>, if used */
	STRING_NOPROXY,         /* List of hosts which should not use the proxy, if used */
	STRING_RTSP_SESSION_ID, /* Session ID to use */
	STRING_RTSP_STREAM_URI, /* Stream URI for this request */
	STRING_RTSP_TRANSPORT,  /* Transport for this session */
	STRING_SSH_PRIVATE_KEY, /* path to the private key file for auth */
	STRING_SSH_PUBLIC_KEY,  /* path to the public key file for auth */
	STRING_SSH_HOST_PUBLIC_KEY_MD5, /* md5 of host public key in ascii hex */
	STRING_SSH_HOST_PUBLIC_KEY_SHA256, /* sha256 of host public key in base64 */
	STRING_SSH_KNOWNHOSTS,  /* file name of knownhosts file */
	STRING_PROXY_SERVICE_NAME, /* Proxy service name */
	STRING_SERVICE_NAME,    /* Service name */
	STRING_MAIL_FROM,
	STRING_MAIL_AUTH,
	STRING_TLSAUTH_USERNAME,  /* TLS auth <username> */
	STRING_TLSAUTH_USERNAME_PROXY, /* TLS auth <username> */
	STRING_TLSAUTH_PASSWORD,  /* TLS auth <password> */
	STRING_TLSAUTH_PASSWORD_PROXY, /* TLS auth <password> */
	STRING_BEARER,                /* <bearer>, if used */
	STRING_UNIX_SOCKET_PATH,      /* path to Unix socket, if used */
	STRING_TARGET,                /* CURLOPT_REQUEST_TARGET */
	STRING_DOH,                   /* CURLOPT_DOH_URL */
	STRING_ALTSVC,                /* CURLOPT_ALTSVC */
	STRING_HSTS,                  /* CURLOPT_HSTS */
	STRING_SASL_AUTHZID,          /* CURLOPT_SASL_AUTHZID */
	STRING_DNS_SERVERS,
	STRING_DNS_INTERFACE,
	STRING_DNS_LOCAL_IP4,
	STRING_DNS_LOCAL_IP6,
	STRING_SSL_EC_CURVES,
	STRING_AWS_SIGV4, /* Parameters for V4 signature */

	/* -- end of null-terminated strings -- */

	STRING_LASTZEROTERMINATED,

	/* -- below this are pointers to binary data that cannot be strdup'ed. --- */

	STRING_COPYPOSTFIELDS,  /* if POST, set the fields' values here */

	STRING_LAST /* not used, just an end-of-list marker */
};

enum dupblob {
	BLOB_CERT,
	BLOB_CERT_PROXY,
	BLOB_KEY,
	BLOB_KEY_PROXY,
	BLOB_SSL_ISSUERCERT,
	BLOB_SSL_ISSUERCERT_PROXY,
	BLOB_CAINFO,
	BLOB_CAINFO_PROXY,
	BLOB_LAST
};

#endif