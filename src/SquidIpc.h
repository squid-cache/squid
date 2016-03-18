/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 54    Interprocess Communication */

#ifndef SQUID_SQUIDIPC_H_
#define SQUID_SQUIDIPC_H_

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

#endif /* SQUID_SQUIDIPC_H_ */

