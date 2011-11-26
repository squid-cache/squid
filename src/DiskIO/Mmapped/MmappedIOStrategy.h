#ifndef SQUID_MMAPPEDIOSTRATEGY_H
#define SQUID_MMAPPEDIOSTRATEGY_H
#include "DiskIO/DiskIOStrategy.h"

class MmappedIOStrategy : public DiskIOStrategy
{

public:
    virtual bool shedLoad();
    virtual int load();
    virtual RefCount<DiskFile> newFile(char const *path);
    virtual bool unlinkdUseful() const;
    virtual void unlinkFile (char const *);
};

#endif /* SQUID_MMAPPEDIOSTRATEGY_H */
