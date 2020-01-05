/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "libltdl/ltdl.h" /* generated file */
#include "LoadableModule.h"

// Note: We must use preprocessor instead of C ifs because if dlopen()
// is seen by the static linker, the linker will complain.

LoadableModule::LoadableModule(const String &aName): theName(aName), theHandle(0)
{
    // Initialise preloaded symbol lookup table.
    LTDL_SET_PRELOADED_SYMBOLS();
    if (lt_dlinit() != 0)
        throw TexcHere("internal error: cannot initialize libtool module loader");
}

LoadableModule::~LoadableModule()
{
    if (loaded())
        unload();
    assert(lt_dlexit() == 0); // XXX: replace with a warning
}

bool
LoadableModule::loaded() const
{
    return theHandle != 0;
}

void
LoadableModule::load(int mode)
{
    if (loaded())
        throw TexcHere("internal error: reusing LoadableModule object");

    theHandle = openModule(mode);

    if (!loaded())
        throw TexcHere(errorMsg());
}

void
LoadableModule::unload()
{
    if (!loaded())
        throw TexcHere("internal error: unloading not loaded module");

    if (!closeModule())
        throw TexcHere(errorMsg());

    theHandle = 0;
}

void *
LoadableModule::openModule(int mode)
{
    return lt_dlopen(theName.termedBuf());
}

bool
LoadableModule::closeModule()
{
    // we cast to avoid including ltdl.h in LoadableModule.h
    return lt_dlclose(static_cast<lt_dlhandle>(theHandle)) == 0;
}

const char *
LoadableModule::errorMsg()
{
    return lt_dlerror();
}

