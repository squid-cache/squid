/*
 * DEBUG: section 54    Interprocess Communication
 *
 */

#include "squid.h"
#include "ipc/mem/Page.h"

#if HAVE_IOSTREAM
#include <iostream>
#endif

std::ostream &Ipc::Mem::operator <<(std::ostream &os, const PageId &page)
{
    return os << "sh_page" << page.pool << '.' << page.number;
}
