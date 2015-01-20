/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

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

