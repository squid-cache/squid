#ifndef ICAP_LOG_H_
#define ICAP_LOG_H_

#include "AccessLogEntry.h"
#include "RefCount.h"

typedef RefCount<AccessLogEntry> AccessLogEntryPointer;
class AccessLogEntry;
class ACLChecklist;

void icapLogClose();
void icapLogOpen();
void icapLogRotate();
void icapLogLog(AccessLogEntryPointer &al, ACLChecklist * checklist);

extern int IcapLogfileStatus;

#endif /*ICAP_LOG_H_*/
