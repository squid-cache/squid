/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 29    Authenticator */

#include "squid.h"
#include "auth/Config.h"
#include "auth/Gadgets.h"
#include "auth/Scheme.h"
#include "globals.h"

std::vector<Auth::Scheme::Pointer> *Auth::Scheme::_Schemes = NULL;

void
Auth::Scheme::AddScheme(Auth::Scheme::Pointer instance)
{
    iterator i = GetSchemes().begin();

    while (i != GetSchemes().end()) {
        assert(strcmp((*i)->type(), instance->type()) != 0);
        ++i;
    }

    GetSchemes().push_back(instance);
}

Auth::Scheme::Pointer
Auth::Scheme::Find(const char *typestr)
{
    for (iterator i = GetSchemes().begin(); i != GetSchemes().end(); ++i) {
        if (strcmp((*i)->type(), typestr) == 0)
            return *i;
    }

    return Auth::Scheme::Pointer(NULL);
}

std::vector<Auth::Scheme::Pointer> &
Auth::Scheme::GetSchemes()
{
    if (!_Schemes)
        _Schemes = new std::vector<Auth::Scheme::Pointer>;

    return *_Schemes;
}

/**
 * Called when a graceful shutdown is to occur of each scheme module.
 * On completion the auth components are to be considered deleted.
 * None will be available globally. Some may remain around for their
 * currently active connections to close, but only those active
 * connections will retain pointers to them.
 */
void
Auth::Scheme::FreeAll()
{
    assert(shutting_down);

    while (GetSchemes().size()) {
        Auth::Scheme::Pointer scheme = GetSchemes().back();
        GetSchemes().pop_back();
        scheme->shutdownCleanup();
    }
}

