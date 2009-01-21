/*
 * $Id$
 *
 *  SQUID_VERSION - String for version id of this distribution
 */

/*
 * SQUID_VERSION is now the automake "VERSION" string.
 */

#ifndef SQUID_RELEASE_TIME
#define SQUID_RELEASE_TIME squid_curtime
#endif

#ifndef APP_SHORTNAME
#define APP_SHORTNAME "squid"
#endif
#ifndef APP_FULLNAME
#define APP_FULLNAME  PACKAGE "/" VERSION
#endif
