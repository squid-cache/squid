/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 77    Client Database */

#include "squid.h"
#include "base/RunnersRegistry.h"
#include "clientdb/Cache.h"
#include "mgr/Registration.h"
#include "SquidConfig.h"

namespace ClientDb
{

/// hooks the ClientDb into Squid's Runner API
class Runner: public RegisteredRunner
{
public:
    /* RegisteredRunner API */
    virtual void useConfig() override {
        if (Config.onoff.client_db)
            Mgr::RegisterAction("client_list", "Cache Client List", ClientDb::Report, 0, 1);
    }
    virtual void finishShutdown() override {
        ClientDb::Cache.clear();
    }
};

RunnerRegistrationEntry(Runner);

} // namespace ClientDb
