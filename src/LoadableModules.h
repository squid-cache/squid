/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_LOADABLEMODULES_H
#define SQUID_SRC_LOADABLEMODULES_H

#include "sbuf/forward.h"

// TODO: add reporting for cachemgr
// TODO: add reconfiguration support

/// list of library filenames to load dynamically
void LoadableModulesConfigure(const SBufList &);

#endif /* SQUID_SRC_LOADABLEMODULES_H */

