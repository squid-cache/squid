/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_PROXYP_FORWARD_H
#define SQUID_SRC_PROXYP_FORWARD_H

#include "base/RefCount.h"

namespace ProxyProtocol
{

class Header;

typedef RefCount<Header> HeaderPointer;

}

#endif /* SQUID_SRC_PROXYP_FORWARD_H */

