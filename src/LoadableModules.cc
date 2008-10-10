#include "squid.h"
#include "wordlist.h"
#include "LoadableModule.h"
#include "LoadableModules.h"

static void
LoadModule(const char *fname)
{
    debugs(1, 1, "loading Squid module from '" << fname << "'");

    LoadableModule *m = new LoadableModule(fname);
    m->load();
    debugs(1, 2, "loaded Squid module from '" << fname << "'");

    //TODO: TheModules.push_back(m);
}

void
LoadableModulesConfigure(const wordlist *names)
{
    int count = 0;
    for (const wordlist *i = names; i; i = i->next, ++count)
        LoadModule(i->key);
    debugs(1, 1, "Squid modules loaded: " << count);
}
