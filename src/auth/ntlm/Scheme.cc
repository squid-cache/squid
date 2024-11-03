/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/ntlm/Config.h"
#include "auth/ntlm/Scheme.h"
#include "base/RunnersRegistry.h"
#include "debug/Messages.h"
#include "debug/Stream.h"
#include "helper.h"

class NtlmAuthRr : public RegisteredRunner
{
public:
    /* RegisteredRunner API */
    void bootstrapConfig() override {
        const char *type = Auth::Ntlm::Scheme::GetInstance()->type();
        debugs(29, 2, "Initialized Authentication Scheme '" << type << "'");
    }
};

DefineRunnerRegistrator(NtlmAuthRr);

Auth::Scheme::Pointer
Auth::Ntlm::Scheme::GetInstance()
{
    static Auth::Scheme::Pointer _instance;

    if (!_instance) {
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
    // TODO: destruct any active Ntlm::Config objects via runner
    debugs(29, 2, "Shutdown: NTLM authentication.");
}

Auth::SchemeConfig *
Auth::Ntlm::Scheme::createConfig()
{
    Auth::Ntlm::Config *ntlmCfg = new Auth::Ntlm::Config;
    return dynamic_cast<Auth::SchemeConfig*>(ntlmCfg);
}

