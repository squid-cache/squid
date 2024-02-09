/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SBUF_STRINGCONVERT_H
#define SQUID_SRC_SBUF_STRINGCONVERT_H

#include "sbuf/SBuf.h"
#include "SquidString.h"

/// create a new SBuf from a String by copying contents
inline SBuf
StringToSBuf(const String &s)
{
    return SBuf(s.rawBuf(), s.size());
}

/** create a new String from a SBuf by copying contents
 * \deprecated
 */
inline String
SBufToString(const SBuf &s)
{
    String rv;
    rv.assign(s.rawContent(), s.length());
    return rv;
}

#endif /* SQUID_SRC_SBUF_STRINGCONVERT_H */

