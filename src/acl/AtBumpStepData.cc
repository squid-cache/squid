#include "squid.h"
#include "acl/Checklist.h"
#include "acl/AtBumpStepData.h"
#include "cache_cf.h"
#include "Debug.h"
#include "wordlist.h"

ACLAtStepData::ACLAtStepData()
{}

ACLAtStepData::ACLAtStepData(ACLAtStepData const &old)
{
    values.assign(old.values.begin(), old.values.end());
}

ACLAtStepData::~ACLAtStepData()
{
}

bool
ACLAtStepData::match(Ssl::BumpStep  toFind)
{
    for (std::list<Ssl::BumpStep>::const_iterator it = values.begin(); it != values.end(); ++it) {
        if (*it == toFind)
            return true;
    }
    return false;
}

SBufList
ACLAtStepData::dump() const
{
    SBufList sl;
    for (std::list<Ssl::BumpStep>::const_iterator it = values.begin(); it != values.end(); ++it) {
        sl.push_back(SBuf(*it == Ssl::bumpStep1 ? "step1" : 
                          *it == Ssl::bumpStep2 ? "step2" : 
                          *it == Ssl::bumpStep3 ? "step3" : "???"));
    }
    return sl;
}

void
ACLAtStepData::parse()
{
    while (const char *t = strtokFile()) {
        if (strcasecmp(t, "step1") == 0) {
            values.push_back(Ssl::bumpStep1);
        } else if (strcasecmp(t, "step2") == 0) {
            values.push_back(Ssl::bumpStep2);
        } else if (strcasecmp(t, "step3") == 0) {
            values.push_back(Ssl::bumpStep3);
        } else {
            debugs(28, DBG_CRITICAL, "FATAL: invalid AtStep step: " << t);
            self_destruct();
        }
    }
}

bool
ACLAtStepData::empty() const
{
    return values.empty();
}

ACLAtStepData *
ACLAtStepData::clone() const
{
    return new ACLAtStepData(*this);
}
