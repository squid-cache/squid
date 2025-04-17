/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "debug/Messages.h"
#include "LoadableModule.h"
#include "LoadableModules.h"
#include "sbuf/List.h"

static void
LoadModule(const SBuf &fname)
{
    debugs(1, DBG_IMPORTANT, "Loading Squid module from '" << fname << "'");

    const auto m = new LoadableModule(fname);
    m->load();
    debugs(1, 2, "Loaded Squid module from '" << fname << "'");

    //TODO: TheModules.push_back(m);
}

void
LoadableModulesConfigure(const SBufList &names)
{
    for (const auto &name : names) {
        LoadModule(name);
    }
    debugs(1, Important(25), "Squid plugin modules loaded: " << names.size());
}

