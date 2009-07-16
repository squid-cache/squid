#include "squid.h"
#include "icap_log.h"
#include "AccessLogEntry.h"

int IcapLogfileStatus = LOG_DISABLE;

void
icapLogOpen()
{
    customlog *log;

    for (log = Config.Log.icaplogs; log; log = log->next) {
        if (log->type == CLF_NONE)
            continue;

        if (log->type == CLF_AUTO)
            log->type = CLF_ICAP_SQUID;

        log->logfile = logfileOpen(log->filename, MAX_URL << 1, 1);

        IcapLogfileStatus = LOG_ENABLE;
    }
}

void 
icapLogClose()
{
    customlog *log;

    for (log = Config.Log.icaplogs; log; log = log->next) {
        if (log->logfile) {
            logfileClose(log->logfile);
            log->logfile = NULL;
        }
    }
}

void
icapLogRotate()
{
    for (customlog* log = Config.Log.icaplogs; log; log = log->next) {
        if (log->logfile) {
            logfileRotate(log->logfile);
        }
    }
}

void icapLogLog(AccessLogEntry *al, ACLChecklist * checklist)
{
    if (IcapLogfileStatus == LOG_ENABLE)
        accessLogLogTo(Config.Log.icaplogs, al, checklist);
}
