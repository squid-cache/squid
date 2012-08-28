#ifndef _getnameinfo_h
#define _getnameinfo_h
/*
 * Reconstructed from KAME getnameinfo.c (in lib/)
 */

#if !HAVE_GETNAMEINFO

/* RFC 2553 / Posix resolver */
SQUIDCEXTERN int xgetnameinfo(const struct sockaddr *sa,
                              socklen_t salen,
                              char *host,
                              size_t hostlen,
                              char *serv,
                              size_t servlen,
                              int flags );
#define getnameinfo	xgetnameinfo

#endif /* HAVE_GETNAMEINFO */
#endif /* _getnameinfo_h */
