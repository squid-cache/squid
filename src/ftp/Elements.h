/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FTP_ELEMENTS_H
#define SQUID_FTP_ELEMENTS_H

#include "http/forward.h"
#include "http/StatusCode.h"
#include "sbuf/forward.h"

namespace AnyP
{
class ProtocolVersion;
}

namespace Ftp
{

/// Protocol version to use in Http::Message structures wrapping FTP messages.
AnyP::ProtocolVersion ProtocolVersion();

/// Create an internal HttpReply structure to house FTP control response info.
HttpReply *HttpReplyWrapper(const int ftpStatus, const char *ftpReason, const Http::StatusCode httpStatus, const int64_t clen);

/* FTP Commands used by Squid. ALLCAPS case. Safe for static initializaton. */
const SBuf &cmdAppe();
const SBuf &cmdAuth();
const SBuf &cmdCwd();
const SBuf &cmdDele();
const SBuf &cmdEprt();
const SBuf &cmdEpsv();
const SBuf &cmdList();
const SBuf &cmdMkd();
const SBuf &cmdMlsd();
const SBuf &cmdMlst();
const SBuf &cmdNlst();
const SBuf &cmdRetr();
const SBuf &cmdRmd();
const SBuf &cmdRnfr();
const SBuf &cmdRnto();
const SBuf &cmdSmnt();
const SBuf &cmdStat();
const SBuf &cmdStor();
const SBuf &cmdStou();
const SBuf &cmdUser();

/// whether this is an informational 1xx response status code
inline bool Is1xx(const int sc) { return Http::scContinue <= sc && sc < Http::scOkay; }

} // namespace Ftp

#endif /* SQUID_FTP_ELEMENTS_H */

