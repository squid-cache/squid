/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_PROXYP_FORWARD_H
#define _SQUID_SRC_PROXYP_FORWARD_H

namespace ProxyProtocol
{

class Message;

typedef RefCount<Message> MessagePointer;

}

#endif /* _SQUID_SRC_PROXYP_FORWARD_H */

