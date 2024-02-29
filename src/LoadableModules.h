/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_LOADABLEMODULES_H
#define SQUID_SRC_LOADABLEMODULES_H

// TODO: add reporting for cachemgr
// TODO: add reconfiguration support

class wordlist;
void LoadableModulesConfigure(const wordlist *names);

#endif /* SQUID_SRC_LOADABLEMODULES_H */

