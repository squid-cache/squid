#include "config.h"
#include "log/Config.h"
#include "log/Tokens.h"
#include "protos.h"

Log::LogConfig Log::TheConfig;

void
Log::LogConfig::parseFormats()
{
    char *name, *def;

    if ((name = strtok(NULL, w_space)) == NULL)
        self_destruct();

    if ((def = strtok(NULL, "\r\n")) == NULL) {
        self_destruct();
        return;
    }

    debugs(3, 2, "Logformat for '" << name << "' is '" << def << "'");

    logformat *nlf = new logformat(name);

    if (!accessLogParseLogFormat(&nlf->format, def)) {
        self_destruct();
        return;
    }

    // add to global config list
    nlf->next = logformats;
    logformats = nlf;
}
