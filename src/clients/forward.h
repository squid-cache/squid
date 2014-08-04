#ifndef SQUID_CLIENTS_FORWARD_H
#define SQUID_CLIENTS_FORWARD_H

class FwdState;
class HttpRequest;

/**
 * \defgroup ServerProtocolFTPAPI Server-Side FTP API
 * \ingroup ServerProtocol
 */

/// \ingroup ServerProtocolFTPAPI
void ftpStart(FwdState *);
/// \ingroup ServerProtocolFTPAPI
const char *ftpUrlWith2f(HttpRequest *);

void ftpGatewayServerStart(FwdState *const);

#endif /* SQUID_CLIENTS_FORWARD_H */
