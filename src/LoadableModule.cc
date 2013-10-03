/*
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
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
#	if XSTD_USE_LIBLTDL
    // Initialise preloaded symbol lookup table.
    LTDL_SET_PRELOADED_SYMBOLS();
    if (lt_dlinit() != 0)
        throw TexcHere("internal error: cannot initialize libtool module loader");
#	endif
}

LoadableModule::~LoadableModule()
{
    if (loaded())
        unload();
#	if XSTD_USE_LIBLTDL
    assert(lt_dlexit() == 0); // XXX: replace with a warning
#	endif
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
#	if XSTD_USE_LIBLTDL
    return lt_dlopen(theName.termedBuf());
#	else
    return dlopen(theName.termedBuf(),
                  mode == lmNow ? RTLD_NOW : RTLD_LAZY);
#	endif
}

bool LoadableModule::closeModule()
{
#	if XSTD_USE_LIBLTDL
    // we cast to avoid including ltdl.h in LoadableModule.h
    return lt_dlclose(static_cast<lt_dlhandle>(theHandle)) == 0;
#	else
    return dlclose(theHandle) == 0;
#	endif
}

const char *LoadableModule::errorMsg()
{
#	if XSTD_USE_LIBLTDL
    return lt_dlerror();
#	else
    return dlerror();
#	endif
}
