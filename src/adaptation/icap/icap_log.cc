#include "squid.h"
#include "icap_log.h"
#include "AccessLogEntry.h"
#include "log/File.h"
#include "log/Formats.h"

int IcapLogfileStatus = LOG_DISABLE;

void
icapLogOpen()
{
    customlog *log;

    for (log = Config.Log.icaplogs; log; log = log->next) {
        if (log->type == Log::Format::CLF_NONE)
            continue;

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
