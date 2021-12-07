/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ssl/Config.h"

Ssl::Config Ssl::TheConfig;

Ssl::Config::Config():
#if USE_SSL_CRTD
    ssl_crtd(NULL),
#endif
    ssl_crt_validator(NULL)
{
    ssl_crt_validator_Children.concurrency = 1;
}

Ssl::Config::~Config()
{
#if USE_SSL_CRTD
    xfree(ssl_crtd);
#endif
    xfree(ssl_crt_validator);
}

