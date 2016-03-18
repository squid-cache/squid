/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 61    Redirector */

#ifndef SQUID_REDIRECT_H_
#define SQUID_REDIRECT_H_

#include "helper.h"

enum TimeoutAction {toutActBypass, toutActFail, toutActRetry, toutActUseConfiguredResponse};

class ClientHttpRequest;

void redirectInit(void);
void redirectShutdown(void);
void redirectStart(ClientHttpRequest *, HLPCB *, void *);
void storeIdStart(ClientHttpRequest *, HLPCB *, void *);

#endif /* SQUID_REDIRECT_H_ */

