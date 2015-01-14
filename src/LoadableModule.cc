/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

/* The original code has this constant ./configure-able.
 * The "#else" branches use raw dlopen interface and have not been tested.
 * We can remove that code if we are going to rely on libtool's ltdl in
 * all environments. */
#define XSTD_USE_LIBLTDL 1

#if XSTD_USE_LIBLTDL
#include "libltdl/ltdl.h" /* generated file */
#else
#include <dlfcn.h>
#endif

#include "base/TextException.h"
#include "LoadableModule.h"

// Note: We must use preprocessor instead of C ifs because if dlopen()
// is seen by the static linker, the linker will complain.

LoadableModule::LoadableModule(const String &aName): theName(aName), theHandle(0)
{
#   if XSTD_USE_LIBLTDL
    // Initialise preloaded symbol lookup table.
    LTDL_SET_PRELOADED_SYMBOLS();
    if (lt_dlinit() != 0)
        throw TexcHere("internal error: cannot initialize libtool module loader");
#   endif
}

LoadableModule::~LoadableModule()
{
    if (loaded())
        unload();
#   if XSTD_USE_LIBLTDL
    assert(lt_dlexit() == 0); // XXX: replace with a warning
#   endif
}

bool LoadableModule::loaded() const
{
    return theHandle != 0;
}

void LoadableModule::load(int mode)
{
    if (loaded())
        throw TexcHere("internal error: reusing LoadableModule object");

    theHandle = openModule(mode);

    if (!loaded())
        throw TexcHere(errorMsg());
}

void LoadableModule::unload()
{
    if (!loaded())
        throw TexcHere("internal error: unloading not loaded module");

    if (!closeModule())
        throw TexcHere(errorMsg());

    theHandle = 0;
}

void *LoadableModule::openModule(int mode)
{
#   if XSTD_USE_LIBLTDL
    return lt_dlopen(theName.termedBuf());
#   else
    return dlopen(theName.termedBuf(),
                  mode == lmNow ? RTLD_NOW : RTLD_LAZY);
#   endif
}

bool LoadableModule::closeModule()
{
#   if XSTD_USE_LIBLTDL
    // we cast to avoid including ltdl.h in LoadableModule.h
    return lt_dlclose(static_cast<lt_dlhandle>(theHandle)) == 0;
#   else
    return dlclose(theHandle) == 0;
#   endif
}

const char *LoadableModule::errorMsg()
{
#   if XSTD_USE_LIBLTDL
    return lt_dlerror();
#   else
    return dlerror();
#   endif
}

