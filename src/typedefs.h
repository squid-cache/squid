/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_TYPEDEFS_H
#define SQUID_TYPEDEFS_H

#include "anyp/ProtocolType.h"
#include "enums.h"

/* disk.c / diskd.c callback typedefs */
typedef void DRCB(int, const char *buf, int size, int errflag, void *data);
/* Disk read CB */
typedef void DWCB(int, int, size_t, void *);    /* disk write CB */

#include "anyp/ProtocolType.h"
class CachePeer;
typedef void IRCB(CachePeer *, peer_t, AnyP::ProtocolType, void *, void *data);

#endif /* SQUID_TYPEDEFS_H */

