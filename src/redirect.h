/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

#endif /* SQUID_SRC_REDIRECT_H */

