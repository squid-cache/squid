/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_CHARSET_H
#define _SQUID_CHARSET_H

#include "sbuf/SBuf.h"

SBuf Latin1ToUtf8(const char *in);

SBuf Cp1251ToUtf8(const char *in);

#endif /* _SQUID_CHARSET_H */

