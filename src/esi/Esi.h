/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ESI_H
#define SQUID_ESI_H

#include "clientStream.h"
#include "sbuf/SBuf.h"

#if !defined(ESI_STACK_DEPTH_LIMIT)
#define ESI_STACK_DEPTH_LIMIT 20
#endif

/* ESI.c */
extern CSR esiStreamRead;
extern CSCB esiProcessStream;
extern CSD esiStreamDetach;
extern CSS esiStreamStatus;
int esiEnableProcessing (HttpReply *);

namespace Esi
{

typedef SBuf ErrorDetail;
/// prepare an Esi::ErrorDetail for throw on ESI parser internal errors
inline Esi::ErrorDetail Error(const char *msg) { return ErrorDetail(msg); }

} // namespace Esi

#endif /* SQUID_ESI_H */

