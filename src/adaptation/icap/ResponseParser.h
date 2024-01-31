/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID__SRC_ADAPTATION_ICAP_RESPONSEPARSER_H
#define _SQUID__SRC_ADAPTATION_ICAP_RESPONSEPARSER_H

#include "http/one/ResponseParser.h"

namespace Adaptation
{
namespace Icap
{

/// ICAP/1.0 response header parser
class ResponseParser : public Http1::ResponseParser
{
private:
    int parseResponseFirstLine() override;

    /// all ICAP/1.0 responses start with this prefix
    static const SBuf Icap1magic;
};

} // namespace Icap
} // namespace Adaptation

#endif /* _SQUID__SRC_ADAPTATION_ICAP_RESPONSEPARSER_H */
