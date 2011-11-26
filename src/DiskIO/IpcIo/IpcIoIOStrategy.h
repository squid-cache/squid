#ifndef SQUID_IPC_IOIOSTRATEGY_H
#define SQUID_IPC_IOIOSTRATEGY_H
#include "DiskIO/DiskIOStrategy.h"

class IpcIoIOStrategy : public DiskIOStrategy
{

public:
    virtual bool shedLoad();
    virtual int load();
    virtual RefCount<DiskFile> newFile(char const *path);
    virtual bool unlinkdUseful() const;
    virtual void unlinkFile (char const *);
};

#endif /* SQUID_IPC_IOIOSTRATEGY_H */
