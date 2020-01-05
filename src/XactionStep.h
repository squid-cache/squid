/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_XACTIONSTEPS_H
#define SQUID_XACTIONSTEPS_H

enum class XactionStep  {
    enumBegin_ = 0, // for WholeEnum iteration
    unknown = enumBegin_,
    generatingConnect,
#if USE_OPENSSL
    tlsBump1,
    tlsBump2,
    tlsBump3,
#endif
    enumEnd_ // for WholeEnum iteration
};

#endif /* SQUID_XACTIONSTEPS_H */

