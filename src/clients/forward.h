#ifndef SQUID_CLIENTS_FORWARD_H
#define SQUID_CLIENTS_FORWARD_H

class FwdState;
class HttpRequest;

class AsyncJob;
template <class Cbc> class CbcPointer;
typedef CbcPointer<AsyncJob> AsyncJobPointer;

namespace Ftp {

/// A new FTP Gateway job
AsyncJobPointer StartGateway(FwdState *const fwdState);

/// A new FTP Relay job
AsyncJobPointer StartRelay(FwdState *const fwdState);

/**
 * \defgroup ServerProtocolFTPAPI Server-Side FTP API
 * \ingroup ServerProtocol
 */

/// \ingroup ServerProtocolFTPAPI
const char *UrlWith2f(HttpRequest *);

} // namespace Ftp

#endif /* SQUID_CLIENTS_FORWARD_H */
