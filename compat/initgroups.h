/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_INITGROUPS_H
#define SQUID_COMPAT_INITGROUPS_H

#if !HAVE_INITGROUPS

SQUIDCEXTERN int initgroups(const char *user, gid_t group);

#endif
#endif /* SQUID_COMPAT_INITGROUPS_H */

