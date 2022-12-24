/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FTP_PARSING_H
#define SQUID_FTP_PARSING_H

#include "ip/forward.h"

namespace Ftp
{

/// parses and validates "A1,A2,A3,A4,P1,P2" IP,port sequence
bool ParseIpPort(const char *buf, const char *forceIp, Ip::Address &addr);

/// parses and validates EPRT "<d><net-prt><d><net-addr><d><tcp-port><d>"
/// proto,IP,port sequence
bool ParseProtoIpPort(const char *buf, Ip::Address &addr);

/// parses an FTP-quoted quote-escaped path
const char *UnescapeDoubleQuoted(const char *quotedPath);

} // namespace Ftp

#endif /* SQUID_FTP_PARSING_H */

