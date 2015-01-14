/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef ICAP_LOG_H_
#define ICAP_LOG_H_

#include "AccessLogEntry.h"
#include "base/RefCount.h"

typedef RefCount<AccessLogEntry> AccessLogEntryPointer;
class AccessLogEntry;
class ACLChecklist;

void icapLogClose();
void icapLogOpen();
void icapLogRotate();
void icapLogLog(AccessLogEntryPointer &al);

extern int IcapLogfileStatus;

#endif /*ICAP_LOG_H_*/

