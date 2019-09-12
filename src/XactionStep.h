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
    xaStepUnknown = 0,
    xaStepGeneratingConnect,
#if USE_OPENSSL
    xaStepTlsBump1,
    xaStepTlsBump2,
    xaStepTlsBump3,
#endif
    xaStepValuesEnd
} XactionStep;

#endif /* SQUID_XACTIONSTEPS_H */
