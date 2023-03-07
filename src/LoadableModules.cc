/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "debug/Messages.h"
#include "debug/Stream.h"
#include "LoadableModule.h"
#include "LoadableModules.h"
#include "wordlist.h"

static void
LoadModule(const char *fname)
{
    debugs(1, DBG_IMPORTANT, "Loading Squid module from '" << fname << "'");

    LoadableModule *m = new LoadableModule(fname);
    m->load();
    debugs(1, 2, "Loaded Squid module from '" << fname << "'");

    //TODO: TheModules.push_back(m);
}

void
LoadableModulesConfigure(const wordlist *names)
{
    int count = 0;
    for (const wordlist *i = names; i; i = i->next, ++count)
        LoadModule(i->key);
    debugs(1, Important(25), "Squid plugin modules loaded: " << count);
}

