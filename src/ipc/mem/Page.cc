/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#include "squid.h"
#include "ipc/mem/Page.h"

#include <iostream>

std::ostream &Ipc::Mem::operator <<(std::ostream &os, const PageId &page)
{
    return os << "sh_page" << page.pool << '.' << page.number;
}

