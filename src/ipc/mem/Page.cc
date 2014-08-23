/*
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "squid.h"
#include "ipc/mem/Page.h"

#include <iostream>

std::ostream &Ipc::Mem::operator <<(std::ostream &os, const PageId &page)
{
    return os << "sh_page" << page.pool << '.' << page.number;
}
