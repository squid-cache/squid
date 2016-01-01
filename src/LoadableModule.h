/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_LOADABLE_MODULE_H
#define SQUID_LOADABLE_MODULE_H

#include "SquidString.h"

// wrapper for dlopen(3), libltdl, and friends
class LoadableModule
{
public:
    enum LoadMode { lmNow, lmLazy };

public:
    LoadableModule(const String &aName);
    ~LoadableModule();           // unloads if loaded

    bool loaded() const;
    const String &name() const { return theName; }
    const String &error() const { return theError; }

    void load(int mode = lmNow); // throws Texc
    void unload(); // throws Texc

protected:
    String theName;
    String theError;
    void *theHandle;

private:
    void *openModule(int mode);
    bool closeModule();
    const char *errorMsg();
};

#endif

