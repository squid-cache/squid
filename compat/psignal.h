#ifndef __SQUID_PSIGNAL_H
#define __SQUID_PSIGNAL_H

#if HAVE_SIGNAL_H
#include <signal.h>
#endif

extern void psignal(int sig, const char* msg);

#endif /* __SQUID_PSIGNAL_H */
