/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ANYP_FORWARD_H
#define SQUID_SRC_ANYP_FORWARD_H

#include "base/RefCount.h"

namespace AnyP
{

class PortCfg;
typedef RefCount<PortCfg> PortCfgPointer;

class Uri;
class UriScheme;

} // namespace AnyP

#endif /* SQUID_SRC_ANYP_FORWARD_H */

