/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_CHARSET_H
#define _SQUID_CHARSET_H

#ifdef __cplusplus
extern "C"
#else
extern
#endif

char *latin1_to_utf8(char *out, size_t size, const char *in);

#endif /* _SQUID_CHARSET_H */

