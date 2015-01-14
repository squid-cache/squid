/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ipc/Forwarder.h"

//Avoid linker errors about Ipc::Forwarder
void foo_stub_ipc_forwarder()
{
    Ipc::Forwarder foo(NULL,1.0);
}

