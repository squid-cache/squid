/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Strategised.h"
#include "HttpHeader.h"

/*
 *  moved template instantiation into ACLStrategized.cc
 *  to compile on Mac OSX 10.5 Leopard.
 *  This corrects a duplicate symbol error
 */

/* explicit template instantiation required for some systems */

/* XXX: move to ACLHTTPRepHeader or ACLHTTPReqHeader */
template class ACLStrategised<HttpHeader*>;

/* ACLMyPortName + ACLMyPeerName + ACLBrowser */
template class ACLStrategised<const char *>;

/* ACLLocalPort + ACLSslError */
template class ACLStrategised<int>;

