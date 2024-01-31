/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID__SRC_ADAPTATION_ICAP_FORWARD_H
#define _SQUID__SRC_ADAPTATION_ICAP_FORWARD_H

#include "base/RefCount.h"

namespace Adaptation
{

/// RFC 3507 Internet Content Adaptation Protocol (ICAP)
namespace Icap
{

class ResponseParser;
typedef RefCount<Adaptation::Icap::ResponseParser> ResponseParserPointer;

} // namespace Icap
} // namespace Adaptation

#endif /* _SQUID__SRC_ADAPTATION_ICAP_FORWARD_H */

