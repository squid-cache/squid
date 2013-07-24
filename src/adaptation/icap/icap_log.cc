#include "squid.h"
#include "icap_log.h"
#include "AccessLogEntry.h"
#include "acl/FilledChecklist.h"
#include "HttpReply.h"
#include "globals.h"
#include "log/CustomLog.h"
#include "log/File.h"
#include "log/Formats.h"
#include "SquidConfig.h"

int IcapLogfileStatus = LOG_DISABLE;

void
icapLogOpen()
{
    CustomLog *log;

    for (log = Config.Log.icaplogs; log; log = log->next) {
        if (log->type == Log::Format::CLF_NONE)
            continue;

        log->logfile = logfileOpen(log->filename, log->bufferSize, log->fatal);

        IcapLogfileStatus = LOG_ENABLE;
    }
}

void
icapLogClose()
{
    CustomLog *log;

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
    for (CustomLog* log = Config.Log.icaplogs; log; log = log->next) {
        if (log->logfile) {
            logfileRotate(log->logfile);
        }
    }
}

void icapLogLog(AccessLogEntry::Pointer &al)
{
    if (IcapLogfileStatus == LOG_ENABLE) {
        ACLFilledChecklist checklist(NULL, al->adapted_request, NULL);
        if (al->reply) {
            checklist.reply = al->reply;
            HTTPMSGLOCK(checklist.reply);
        }
        accessLogLogTo(Config.Log.icaplogs, al, &checklist);
    }
}
