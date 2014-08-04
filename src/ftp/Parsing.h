#ifndef SQUID_FTP_PARSING_H
#define SQUID_FTP_PARSING_H

#include "ip/forward.h"

namespace Ftp {

// TODO: Document
bool ParseIpPort(const char *buf, const char *forceIp, Ip::Address &addr);
bool ParseProtoIpPort(const char *buf, Ip::Address &addr);
const char *UnescapeDoubleQuoted(const char *quotedPath);

} // namespace Ftp

#endif /* SQUID_FTP_PARSING_H */
