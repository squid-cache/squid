
/*
 * $Id$
 *
 */

#include "squid.h"
#include "ProtoPort.h"

http_port_list::http_port_list(const char *aProtocol)
#if USE_SSL
        :
        http(*this)
#endif
{
    protocol = xstrdup(aProtocol);
}

http_port_list::~http_port_list()
{
    safe_free(name);
    safe_free(defaultsite);
    safe_free(protocol);

#if USE_SSL
    safe_free(cert);
    safe_free(key);
    safe_free(options);
    safe_free(cipher);
    safe_free(cafile);
    safe_free(capath);
    safe_free(dhfile);
    safe_free(sslflags);
#endif
}


#if USE_SSL

https_port_list::https_port_list(): http_port_list("https")
{
}

#endif
