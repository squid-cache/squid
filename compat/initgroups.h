#ifndef SQUID_INITGROUPS_H
#define SQUID_INITGROUPS_H

#if !HAVE_INITGROUPS

SQUIDCEXTERN int initgroups(const char *user, gid_t group);

#endif
#endif /* SQUID_INITGROPS_H */
