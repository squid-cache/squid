#ifndef SQUID_IPC_IODISKIOMODULE_H
#define SQUID_IPC_IODISKIOMODULE_H

#include "DiskIO/DiskIOModule.h"

class IpcIoDiskIOModule : public DiskIOModule
{

public:
    static IpcIoDiskIOModule &GetInstance();
    IpcIoDiskIOModule();
    virtual void init();
    virtual void shutdown();
    virtual char const *type () const;
    virtual DiskIOStrategy* createStrategy();

private:
    static IpcIoDiskIOModule Instance;
};

#endif /* SQUID_IPC_IODISKIOMODULE_H */
