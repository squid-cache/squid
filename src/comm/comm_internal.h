/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMM_COMM_INTERNAL_H
#define SQUID_COMM_COMM_INTERNAL_H

/* misc collection of bits shared by Comm code, but not needed by the rest of Squid. */

bool isOpen(const int fd);
void commStopHalfClosedMonitor(int fd);

#endif

