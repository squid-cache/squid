/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/negotiate/Config.h"
#include "auth/negotiate/Scheme.h"
#include "debug/Messages.h"
#include "debug/Stream.h"
#include "helper.h"

Auth::Scheme::Pointer Auth::Negotiate::Scheme::_instance = nullptr;

Auth::Scheme::Pointer
Auth::Negotiate::Scheme::GetInstance()
{
    if (_instance == nullptr) {
        _instance = new Auth::Negotiate::Scheme();
        AddScheme(_instance);
    }
    return _instance;
}

char const *
Auth::Negotiate::Scheme::type() const
{
    return "negotiate";
}

void
Auth::Negotiate::Scheme::shutdownCleanup()
{
    if (_instance == nullptr)
        return;

    _instance = nullptr;
    debugs(29, Critical(60), "Shutdown: Negotiate authentication.");
}

Auth::SchemeConfig *
Auth::Negotiate::Scheme::createConfig()
{
    Auth::Negotiate::Config *negotiateCfg = new Auth::Negotiate::Config;
    return dynamic_cast<Auth::SchemeConfig*>(negotiateCfg);
}

