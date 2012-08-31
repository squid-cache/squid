#include "squid.h"
#include "cache_cf.h"
#include "Debug.h"
#include "log/Config.h"

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

    debugs(3, 2, "Log Format for '" << name << "' is '" << def << "'");

    ::Format::Format *nlf = new ::Format::Format(name);

    if (!nlf->parse(def)) {
        self_destruct();
        return;
    }

    // add to global config list
    nlf->next = logformats;
    logformats = nlf;
}
