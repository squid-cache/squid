/*
 * $Id: initgroups.h,v 1.1 2004/10/20 22:41:03 hno Exp $
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

extern int initgroups(const char *user, gid_t group);
#endif /* SQUID_INITGROPS_H */
