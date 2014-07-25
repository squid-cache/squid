#ifndef _SQUID_SRC_ANYP_FORWARD_H
#define _SQUID_SRC_ANYP_FORWARD_H

#include "base/RefCount.h"

namespace AnyP
{

class PortCfg;
typedef RefCount<PortCfg> PortCfgPointer;

class UriScheme;

} // namespace AnyP

#endif /* _SQUID_SRC_ANYP_FORWARD_H */

