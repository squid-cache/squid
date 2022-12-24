/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DISKIOMODULE_H
#define SQUID_DISKIOMODULE_H

#include <vector>

/* forward decls */

class CacheManager;

class DiskIOStrategy;

class DiskIOModule
{

public:
    /** Poke all compiled modules for self-setup */
    static void SetupAllModules();
    static void ModuleAdd(DiskIOModule &);
    static void FreeAllModules();

    static DiskIOModule *Find(char const *type);

    /** Find *any* usable disk module. This will look for the 'best'
     * available module for this system.
     */
    static DiskIOModule *FindDefault();
    static std::vector<DiskIOModule*> const &Modules();
    typedef std::vector<DiskIOModule*>::iterator iterator;
    typedef std::vector<DiskIOModule*>::const_iterator const_iterator;
    DiskIOModule();
    virtual ~DiskIOModule() {}

    virtual void init() = 0;
    //virtual void registerWithCacheManager(void);
    virtual void gracefulShutdown() = 0;
    virtual DiskIOStrategy *createStrategy() = 0;

    virtual char const *type () const = 0;
    // Not implemented
    DiskIOModule(DiskIOModule const &);
    DiskIOModule &operator=(DiskIOModule const&);

protected:
    //bool initialised;
    static void RegisterAllModulesWithCacheManager(void);

private:
    static std::vector<DiskIOModule*> &GetModules();
    static std::vector<DiskIOModule*> *_Modules;
};

#endif /* SQUID_DISKIOMODULE_H */

