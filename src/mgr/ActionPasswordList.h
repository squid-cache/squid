/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_MGR_ACTIONPASSWORDLIST_H
#define SQUID_SRC_MGR_ACTIONPASSWORDLIST_H

#include "sbuf/forward.h"

namespace Mgr
{
//TODO: refactor into a std::list
/// list of cachemgr password authorization definitions. Currently a POD.
class ActionPasswordList
{
public:
    ~ActionPasswordList();

    char *passwd = nullptr;
    SBufList actions;
    ActionPasswordList *next = nullptr;
};

} //namespace Mgr

#endif /* SQUID_SRC_MGR_ACTIONPASSWORDLIST_H */

