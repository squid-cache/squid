/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_RELEASE_TIME
#define SQUID_RELEASE_TIME squid_curtime
#endif

/*
 * String for version id of this distribution
 * is now the automake "VERSION" string.
 */

#ifndef APP_SHORTNAME
#define APP_SHORTNAME "squid"
#endif
#ifndef APP_FULLNAME
#define APP_FULLNAME  PACKAGE "/" VERSION
#endif

