/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_XACTIONSTEPS_H
#define SQUID_XACTIONSTEPS_H

typedef enum {
    xstepUnknown = 0,
    xstepGeneratingConnect,
#if USE_OPENSSL
    xstepTlsBump1,
    xstepTlsBump2,
    xstepTlsBump3,
#endif
    xstepValuesEnd
} XactionStep;

#endif /* SQUID_XACTIONSTEPS_H */
