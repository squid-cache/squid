/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_PROXYP_FORWARD_H
#define _SQUID_SRC_PROXYP_FORWARD_H

#include "base/RefCount.h"

namespace ProxyProtocol
{

class Header;

typedef RefCount<Header> HeaderPointer;

}

#endif /* _SQUID_SRC_PROXYP_FORWARD_H */

