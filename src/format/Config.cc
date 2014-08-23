#include "squid.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "format/Config.h"
#include <list>

Format::FmtConfig Format::TheConfig;

void
Format::FmtConfig::parseFormats()
{
    char *name, *def;

    if ((name = ConfigParser::NextToken()) == NULL)
        self_destruct();

    if ((def = ConfigParser::NextQuotedOrToEol()) == NULL) {
        self_destruct();
        return;
    }

    debugs(3, 2, "Custom Format for '" << name << "' is '" << def << "'");

    Format *nlf = new Format(name);

    if (!nlf->parse(def)) {
        self_destruct();
        return;
    }

    // add to global config list
    nlf->next = formats;
    formats = nlf;
}

void
Format::FmtConfig::registerTokens(const String &nsName, TokenTableEntry const *tokenArray)
{
    debugs(46, 2, HERE << " register format tokens for '" << nsName << "'");
    if (tokenArray != NULL)
        tokens.push_back(TokenNamespace(nsName, tokenArray));
    else
        debugs(0, DBG_CRITICAL, "BUG: format tokens for '" << nsName << "' missing!");
}
