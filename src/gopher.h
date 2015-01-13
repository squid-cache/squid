/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 10    Gopher */

#ifndef SQUID_GOPHER_H_
#define SQUID_GOPHER_H_

class FwdState;
class HttpRequest;

/**
 \defgroup ServerProtocolGopherAPI Server-Side Gopher API
 \ingroup ServerProtocol
 */

/// \ingroup ServerProtocolGopherAPI
void gopherStart(FwdState *);

/// \ingroup ServerProtocolGopherAPI
int gopherCachable(const HttpRequest *);

#endif /* SQUID_GOPHER_H_ */

