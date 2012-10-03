#ifndef SQUID_LOADABLE_MODULES_H
#define SQUID_LOADABLE_MODULES_H

// TODO: add reporting for cachemgr
// TODO: add reconfiguration support

class wordlist;
void LoadableModulesConfigure(const wordlist *names);

#endif /* SQUID_LOADABLE_MODULES_H */
