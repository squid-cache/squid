/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_SRC_SQUIDIPC_H
#define SQUID_SRC_SQUIDIPC_H

namespace Ip
{
class Address;
}
pid_t ipcCreate(int type,
                const char *prog,
                const char *const args[],
                const char *name,
                Ip::Address &local_addr,
                int *rfd,
                int *wfd,
                void **hIpc);

#endif /* SQUID_SRC_SQUIDIPC_H */

