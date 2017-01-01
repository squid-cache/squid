/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ESI_H
#define SQUID_ESI_H

#include "clientStream.h"

/* ESI.c */
extern CSR esiStreamRead;
extern CSCB esiProcessStream;
extern CSD esiStreamDetach;
extern CSS esiStreamStatus;
int esiEnableProcessing (HttpReply *);

#endif /* SQUID_ESI_H */

