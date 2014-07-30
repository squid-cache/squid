#ifndef SQUID_HTTP_REGISTEREDHEADERS_H
#define SQUID_HTTP_REGISTEREDHEADERS_H

/// recognized or "known" header fields; and the RFC which defines them (or not)
typedef enum {
    HDR_BAD_HDR = -1,
    HDR_ACCEPT = 0,                     /**< RFC 2608, 2616 */
    HDR_ACCEPT_CHARSET,                 /**< RFC 2608, 2616 */
    HDR_ACCEPT_ENCODING,                /**< RFC 2608, 2616 */
    /*HDR_ACCEPT_FEATURES,*/            /* experimental RFC 2295 */
    HDR_ACCEPT_LANGUAGE,                /**< RFC 2608, 2616 */
    HDR_ACCEPT_RANGES,                  /**< RFC 2608, 2616 */
    HDR_AGE,                            /**< RFC 2608, 2616 */
    HDR_ALLOW,                          /**< RFC 2608, 2616 */
    /*HDR_ALTERNATES,*/                 /* deprecated RFC 2068, 2295 */
    HDR_AUTHORIZATION,                  /**< RFC 2608, 2616, 4559 */
    HDR_CACHE_CONTROL,                  /**< RFC 2608, 2616 */
    HDR_CONNECTION,                     /**< RFC 2608, 2616 */
    HDR_CONTENT_BASE,                   /**< RFC 2608 */
    HDR_CONTENT_DISPOSITION,            /**< RFC 2183, 2616 */
    HDR_CONTENT_ENCODING,               /**< RFC 2608, 2616 */
    HDR_CONTENT_LANGUAGE,               /**< RFC 2608, 2616 */
    HDR_CONTENT_LENGTH,                 /**< RFC 2608, 2616 */
    HDR_CONTENT_LOCATION,               /**< RFC 2608, 2616 */
    HDR_CONTENT_MD5,                    /**< RFC 2608, 2616 */
    HDR_CONTENT_RANGE,                  /**< RFC 2608, 2616 */
    HDR_CONTENT_TYPE,                   /**< RFC 2608, 2616 */
    /*HDR_CONTENT_VERSION,*/            /* deprecated RFC 2608 header. */
    HDR_COOKIE,                         /**< de-facto and RFC 2965 header we may need to erase */
    HDR_COOKIE2,                        /**< obsolete RFC 2965 header we may need to erase */
    HDR_DATE,                           /**< RFC 2608, 2616 */
    /*HDR_DAV,*/                        /* RFC 2518 */
    /*HDR_DEPTH,*/                      /* RFC 2518 */
    /*HDR_DERIVED_FROM,*/               /* deprecated RFC 2608 */
    /*HDR_DESTINATION,*/                /* RFC 2518 */
    HDR_ETAG,                           /**< RFC 2608, 2616 */
    HDR_EXPECT,                         /**< RFC 2608, 2616 */
    HDR_EXPIRES,                        /**< RFC 2608, 2616 */
    HDR_FORWARDED,                      /**< RFC 7239 */
    HDR_FROM,                           /**< RFC 2608, 2616 */
    HDR_HOST,                           /**< RFC 2608, 2616 */
    HDR_HTTP2_SETTINGS,                 /**< HTTP/2.0 upgrade header. see draft-ietf-httpbis-http2-04 */
    /*HDR_IF,*/                         /* RFC 2518 */
    HDR_IF_MATCH,                       /**< RFC 2608, 2616 */
    HDR_IF_MODIFIED_SINCE,              /**< RFC 2608, 2616 */
    HDR_IF_NONE_MATCH,                  /**< RFC 2608, 2616 */
    HDR_IF_RANGE,                       /**< RFC 2608, 2616 */
    /*HDR_IF_UNMODIFIED_SINCE,*/        /**< RFC 2608, 2616 */
    HDR_KEEP_ALIVE,                     /**< obsolete HTTP/1.0 header we may need to erase */
    HDR_KEY,                            /**< experimental RFC Draft draft-fielding-http-key-02 */
    HDR_LAST_MODIFIED,                  /**< RFC 2608, 2616 */
    HDR_LINK,                           /**< RFC 2068 */
    HDR_LOCATION,                       /**< RFC 2608, 2616 */
    /*HDR_LOCK_TOKEN,*/                 /* RFC 2518 */
    HDR_MAX_FORWARDS,                   /**< RFC 2608, 2616 */
    HDR_MIME_VERSION,                   /**< RFC 2626 */
    HDR_NEGOTIATE,                      /**< experimental RFC 2295. Why only this one from 2295? */
    /*HDR_OVERWRITE,*/                  /* RFC 2518 */
    HDR_ORIGIN,                         /* CORS Draft specification (see http://www.w3.org/TR/cors/) */
    HDR_PRAGMA,                         /**< deprecated RFC 2068,2616 header we may need to erase */
    HDR_PROXY_AUTHENTICATE,             /**< RFC 2608, 2616, 2617 */
    HDR_PROXY_AUTHENTICATION_INFO,      /**< RFC 2617 */
    HDR_PROXY_AUTHORIZATION,            /**< RFC 2608, 2616, 2617 */
    HDR_PROXY_CONNECTION,               /**< obsolete Netscape header we may need to erase. */
    HDR_PROXY_SUPPORT,                  /**< RFC 4559 */
    HDR_PUBLIC,                         /**< RFC 2608 */
    HDR_RANGE,                          /**< RFC 2608, 2616 */
    HDR_REFERER,                        /**< RFC 2608, 2616 */
    HDR_REQUEST_RANGE,                  /**< some clients use this, sigh */
    HDR_RETRY_AFTER,                    /**< RFC 2608, 2616 */
    HDR_SERVER,                         /**< RFC 2608, 2616 */
    HDR_SET_COOKIE,                     /**< de-facto standard header we may need to erase */
    HDR_SET_COOKIE2,                    /**< obsolete RFC 2965 header we may need to erase */
    /*HDR_STATUS_URI,*/                 /* RFC 2518 */
    /*HDR_TCN,*/                        /* experimental RFC 2295 */
    HDR_TE,                             /**< RFC 2616 */
    /*HDR_TIMEOUT,*/                    /* RFC 2518 */
    HDR_TITLE,                          /* obsolete draft suggested header */
    HDR_TRAILER,                        /**< RFC 2616 */
    HDR_TRANSFER_ENCODING,              /**< RFC 2608, 2616 */
    HDR_TRANSLATE,                      /**< IIS custom header we may need to erase */
    HDR_UNLESS_MODIFIED_SINCE,          /**< IIS custom header we may need to erase */
    HDR_UPGRADE,                        /**< RFC 2608, 2616 */
    /*HDR_URI,*/                        /* obsolete RFC 2068 header */
    HDR_USER_AGENT,                     /**< RFC 2608, 2616 */
    /*HDR_VARIANT_VARY,*/               /* experimental RFC 2295 */
    HDR_VARY,                           /**< RFC 2608, 2616 */
    HDR_VIA,                            /**< RFC 2608, 2616 */
    HDR_WARNING,                        /**< RFC 2608, 2616 */
    HDR_WWW_AUTHENTICATE,               /**< RFC 2608, 2616, 2617, 4559 */
    HDR_AUTHENTICATION_INFO,            /**< RFC 2617 */
    HDR_X_CACHE,                        /**< Squid custom header */
    HDR_X_CACHE_LOOKUP,                 /**< Squid custom header. temporary hack that became de-facto. TODO remove */
    HDR_X_FORWARDED_FOR,                /**< obsolete Squid custom header */
    HDR_X_REQUEST_URI,                  /**< Squid custom header appended if ADD_X_REQUEST_URI is defined */
    HDR_X_SQUID_ERROR,                  /**< Squid custom header on generated error responses */
#if X_ACCELERATOR_VARY
    HDR_X_ACCELERATOR_VARY,             /**< obsolete Squid custom header. */
#endif
#if USE_ADAPTATION
    HDR_X_NEXT_SERVICES,                /**< Squid custom ICAP header */
#endif
    HDR_SURROGATE_CAPABILITY,           /**< Edge Side Includes (ESI) header */
    HDR_SURROGATE_CONTROL,              /**< Edge Side Includes (ESI) header */
    HDR_FRONT_END_HTTPS,                /**< MS Exchange custom header we may have to add */
    HDR_OTHER,                          /**< internal tag value for "unknown" headers */
    HDR_ENUM_END
} http_hdr_type;

#endif /* SQUID_HTTP_REGISTEREDHEADERS_H */
