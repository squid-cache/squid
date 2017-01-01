/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef WINSVC_H_
#define WINSVC_H_

#if _SQUID_WINDOWS_
int WIN32_StartService(int, char **);
int WIN32_Subsystem_Init(int *, char ***);
void WIN32_sendSignal(int);
void WIN32_SetServiceCommandLine(void);
void WIN32_InstallService(void);
void WIN32_RemoveService(void);
#else /* _SQUID_WINDOWS_ */
inline int WIN32_Subsystem_Init(int *foo, char ***bar) {return 0; } /* NOP */
inline void WIN32_sendSignal(int foo) { return; } /* NOP */
inline void WIN32_SetServiceCommandLine(void) {} /* NOP */
inline void WIN32_InstallService(void) {} /* NOP */
inline  void WIN32_RemoveService(void) {} /* NOP */
#endif /* _SQUID_WINDOWS_ */

#endif /* WINSVC_H_ */

