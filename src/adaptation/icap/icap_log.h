#ifndef ICAP_LOG_H_
#define ICAP_LOG_H_

class AccessLogEntry;
class ACLChecklist;

void icapLogClose();
void icapLogOpen();
void icapLogRotate();
void icapLogLog(AccessLogEntry *al, ACLChecklist * checklist);

extern int IcapLogfileStatus;

#endif /*ICAP_LOG_H_*/
