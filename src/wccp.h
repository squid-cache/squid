/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 80    WCCP Support */

#ifndef SQUID_SRC_WCCP_H
#define SQUID_SRC_WCCP_H

#if USE_WCCP
void wccpInit(void);
void wccpConnectionOpen(void);
void wccpConnectionClose(void);
#endif /* USE_WCCP */

#endif /* SQUID_SRC_WCCP_H */

