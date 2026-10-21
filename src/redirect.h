/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 61    Redirector */

#ifndef SQUID_SRC_REDIRECT_H
#define SQUID_SRC_REDIRECT_H

#include "helper.h"

enum TimeoutAction {toutActBypass, toutActFail, toutActRetry, toutActUseConfiguredResponse};

class ClientHttpRequest;

void redirectInit(void);
void redirectShutdown(void);
void redirectReconfigure();
void redirectStart(ClientHttpRequest *, HLPCB *, void *);
void storeIdStart(ClientHttpRequest *, HLPCB *, void *);

/// Whether the given input uses URI-reference syntax (RFC 9110 Section 10.2.2).
/// Logs a level-0 ERROR message on failures.
/// \prec the given string has been percent-encoded (RFC 3986 Section 2.1)
bool redirectUriIsValid(const char *);

#endif /* SQUID_SRC_REDIRECT_H */

