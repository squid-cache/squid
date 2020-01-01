/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 80    WCCP Support */

#ifndef SQUID_WCCP_H_
#define SQUID_WCCP_H_

#if USE_WCCP
void wccpInit(void);
void wccpConnectionOpen(void);
void wccpConnectionClose(void);
#endif /* USE_WCCP */

#endif /* SQUID_WCCP_H_ */

