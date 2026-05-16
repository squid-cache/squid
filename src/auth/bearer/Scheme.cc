/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/bearer/Config.h"
#include "auth/bearer/Scheme.h"
#include "helper.h"

Auth::Scheme::Pointer Auth::Bearer::Scheme::_instance = nullptr;

Auth::Scheme::Pointer
Auth::Bearer::Scheme::GetInstance()
{
    if (!_instance) {
        _instance = new Bearer::Scheme();
        AddScheme(_instance);
    }
    return _instance;
}

char const *
Auth::Bearer::Scheme::type() const
{
    return "bearer";
}

void
Auth::Bearer::Scheme::shutdownCleanup()
{
    if (!_instance)
        return;

    _instance = nullptr;
    debugs(29, DBG_CRITICAL, "Shutdown: " << type() << " authentication.");
}

Auth::SchemeConfig *
Auth::Bearer::Scheme::createConfig()
{
    return dynamic_cast<SchemeConfig *>(new Bearer::Config);
}
