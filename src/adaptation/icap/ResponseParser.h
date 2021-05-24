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

/** ICAP/1.x protocol response parser
 *
 * Works on a raw character I/O buffer and tokenizes the content into
 * the major CRLF delimited segments of an ICAP/1 response message:
 *
 * \li status-line (version SP status SP reash-phrase)
 * \li mime-header (set of RFC2822 syntax header fields)
 *
 * RFC 3507 ICAP syntax is based on HTTP/1 message syntax (with differences)
 * most of the HTTP/1 response parser can be re-used.
 */
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
