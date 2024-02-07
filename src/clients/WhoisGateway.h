/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 75    WHOIS protocol */

#ifndef SQUID_SRC_CLIENTS_WHOISGATEWAY_H
#define SQUID_SRC_CLIENTS_WHOISGATEWAY_H

#include "clients/forward.h"

/**
 * \defgroup ServerProtocolWhoisAPI Server-Side WHOIS API
 * \ingroup ServerProtocol
 */

/// \ingroup ServerProtocolWhoisAPI
void whoisStart(FwdState *);

#endif /* SQUID_SRC_CLIENTS_WHOISGATEWAY_H */

