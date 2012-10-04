#include "squid.h"
#include "ssl/Config.h"

Ssl::Config Ssl::TheConfig;

Ssl::Config::Config()
#if USE_SSL_CRTD
        :
        ssl_crtd(NULL)
#endif
{
}

Ssl::Config::~Config()
{
#if USE_SSL_CRTD
    xfree(ssl_crtd);
#endif
}
