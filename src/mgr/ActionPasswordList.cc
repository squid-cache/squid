/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "mgr/ActionPasswordList.h"
#include "sbuf/List.h"

Mgr::ActionPasswordList::~ActionPasswordList()
{
    xfree(passwd);
    delete next; // recurse, these lists are usually not long
}

