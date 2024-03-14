/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_LOADABLEMODULE_H
#define SQUID_SRC_LOADABLEMODULE_H

#include "sbuf/SBuf.h"

// wrapper for dlopen(3), libltdl, and friends
class LoadableModule
{
public:
    LoadableModule(const SBuf &aName);
    ~LoadableModule();           // unloads if loaded

    bool loaded() const;
    const SBuf &name() const { return theName; }
    const SBuf &error() const { return theError; }

    void load(); // throws Texc
    void unload(); // throws Texc

protected:
    SBuf theName;
    SBuf theError;
    void *theHandle = nullptr;

private:
    void *openModule();
    bool closeModule();
    const char *errorMsg();
};

#endif /* SQUID_SRC_LOADABLEMODULE_H */

