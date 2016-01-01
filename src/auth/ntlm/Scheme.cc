/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/ntlm/Config.h"
#include "auth/ntlm/Scheme.h"
#include "Debug.h"
#include "helper.h"

Auth::Scheme::Pointer Auth::Ntlm::Scheme::_instance = NULL;

Auth::Scheme::Pointer
Auth::Ntlm::Scheme::GetInstance()
{
    if (_instance == NULL) {
        _instance = new Auth::Ntlm::Scheme();
        AddScheme(_instance);
    }
    return _instance;
}

char const *
Auth::Ntlm::Scheme::type() const
{
    return "ntlm";
}

void
Auth::Ntlm::Scheme::shutdownCleanup()
{
    if (_instance == NULL)
        return;

    _instance = NULL;
    debugs(29, DBG_CRITICAL, "Shutdown: NTLM authentication.");
}

Auth::Config *
Auth::Ntlm::Scheme::createConfig()
{
    Auth::Ntlm::Config *ntlmCfg = new Auth::Ntlm::Config;
    return dynamic_cast<Auth::Config*>(ntlmCfg);
}

