/*
 * $Id: initgroups.h,v 1.2 2004/11/06 22:09:19 hno Exp $
 */
#ifndef SQUID_INITGROUPS_H
#define SQUID_INITGROUPS_H

/* if you have configure you can use this */
#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

SQUIDCEXTERN int initgroups(const char *user, gid_t group);
#endif /* SQUID_INITGROPS_H */
