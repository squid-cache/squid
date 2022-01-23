/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/AdaptationServiceData.h"
#include "acl/Checklist.h"
#include "adaptation/Config.h"
#include "adaptation/ecap/Config.h"
#include "adaptation/icap/Config.h"
#include "adaptation/Service.h"
#include "adaptation/ServiceGroups.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"

void
ACLAdaptationServiceData::parse()
{
    Adaptation::Config::needHistory = true;
    while (char *t = ConfigParser::strtokFile()) {
        if (
#if USE_ECAP
            Adaptation::Ecap::TheConfig.findServiceConfig(t) == NULL &&
#endif
#if ICAP_CLIENT
            Adaptation::Icap::TheConfig.findServiceConfig(t) == NULL &&
#endif
            Adaptation::FindGroup(t) == NULL) {
            debugs(28, DBG_CRITICAL, "FATAL: Adaptation service/group " << t << " in adaptation_service acl is not defined");
            self_destruct();
        }
        insert(t);
    }
}

ACLData<char const *> *
ACLAdaptationServiceData::clone() const
{
    return new ACLAdaptationServiceData(*this);
}

