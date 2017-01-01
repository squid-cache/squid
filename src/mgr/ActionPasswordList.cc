/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "mgr/ActionPasswordList.h"
#include "wordlist.h"

Mgr::ActionPasswordList::~ActionPasswordList()
{
    safe_free(passwd);
    wordlistDestroy(&actions);
    delete next;
}

