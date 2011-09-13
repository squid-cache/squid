#ifndef SQUID_MMAPPEDDISKIOMODULE_H
#define SQUID_MMAPPEDDISKIOMODULE_H

#include "DiskIO/DiskIOModule.h"

class MmappedDiskIOModule : public DiskIOModule
{

public:
    static MmappedDiskIOModule &GetInstance();
    MmappedDiskIOModule();
    virtual void init();
    virtual void shutdown();
    virtual char const *type () const;
    virtual DiskIOStrategy* createStrategy();

private:
    static MmappedDiskIOModule Instance;
};

#endif /* SQUID_MMAPPEDDISKIOMODULE_H */
