#ifndef _SQUID_DRAND48_H
#define _SQUID_DRAND48_H

#if !HAVE_DRAND48
#define HAVE_DRAND48 1
SQUIDCEXTERN double drand48(void);
#endif

#endif
