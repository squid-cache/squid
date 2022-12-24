/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CLIENTS_FORWARD_H
#define SQUID_CLIENTS_FORWARD_H

#include "sbuf/forward.h"

class FwdState;
class HttpRequest;

class AsyncJob;
template <class Cbc> class CbcPointer;
typedef CbcPointer<AsyncJob> AsyncJobPointer;

namespace Http
{
class Tunneler;
class TunnelerAnswer;
}

namespace Ftp
{

/// A new FTP Gateway job
void StartGateway(FwdState *const fwdState);

/// A new FTP Relay job
void StartRelay(FwdState *const fwdState);

/** Construct an URI with leading / in PATH portion for use by CWD command
 *  possibly others. FTP encodes absolute paths as beginning with '/'
 *  after the initial URI path delimiter, which happens to be / itself.
 *  This makes FTP absolute URI appear as:  ftp:host:port//root/path
 *  To encompass older software which compacts multiple // to / in transit
 *  We use standard URI-encoding on the second / making it
 *  ftp:host:port/%2froot/path  AKA 'the FTP %2f hack'.
 *
 * TODO: Should be an AnyP::Uri member
 */
const SBuf &UrlWith2f(HttpRequest *);

} // namespace Ftp

#endif /* SQUID_CLIENTS_FORWARD_H */

