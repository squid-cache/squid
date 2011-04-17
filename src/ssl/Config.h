/*
 * $Id$
 */

#ifndef SQUID_SSL_CONFIG_H
#define SQUID_SSL_CONFIG_H

namespace Ssl
{

class Config
{
public:
#if USE_SSL_CRTD
    char *ssl_crtd; ///< Name of external ssl_crtd application.
    /// The number of processes spawn for ssl_crtd.
    int ssl_crtd_n_running;
#endif
    Config();
    ~Config();
private:
    Config(const Config &); // not implemented
    Config &operator =(const Config &); // not implemented
};

extern Config TheConfig;

} // namespace Ssl
#endif
