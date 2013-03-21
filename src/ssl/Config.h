#ifndef SQUID_SSL_CONFIG_H
#define SQUID_SSL_CONFIG_H

#include "HelperChildConfig.h"

namespace Ssl
{

class Config
{
public:
#if USE_SSL_CRTD
    char *ssl_crtd; ///< Name of external ssl_crtd application.
    /// The number of processes spawn for ssl_crtd.
    HelperChildConfig ssl_crtdChildren;
#endif
    char *ssl_crt_validator;
    HelperChildConfig ssl_crt_validator_Children;
    Config():
#if USE_SSL_CRTD
            ssl_crtd(NULL),
#endif
            ssl_crt_validator(NULL) {}

    ~Config();
private:
    Config(const Config &); // not implemented
    Config &operator =(const Config &); // not implemented
};

extern Config TheConfig;

} // namespace Ssl
#endif
