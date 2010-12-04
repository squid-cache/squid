#ifndef SQUID_IDENT_CONFIG_H
#define SQUID_IDENT_CONFIG_H

#if USE_IDENT

#include "acl/Acl.h"

namespace Ident
{

class IdentConfig
{
public:
    acl_access *identLookup;
    time_t timeout;
};

extern IdentConfig TheConfig;

} // namespace Ident

#endif /* USE_IDENT */
#endif /* SQUID_IDENT_CONFIG_H */
