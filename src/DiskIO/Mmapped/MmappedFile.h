#ifndef SQUID_MMAPPEDFILE_H
#define SQUID_MMAPPEDFILE_H

#include "cbdata.h"
#include "DiskIO/DiskFile.h"
#include "DiskIO/IORequestor.h"

class MmappedFile : public DiskFile
{

public:
    void *operator new(size_t);
    void operator delete(void *);
    MmappedFile(char const *path);
    ~MmappedFile();
    virtual void open(int flags, mode_t mode, RefCount<IORequestor> callback);
    virtual void create(int flags, mode_t mode, RefCount<IORequestor> callback);
    virtual void read(ReadRequest *);
    virtual void write(WriteRequest *);
    virtual void close();
    virtual bool error() const;
    virtual int getFD() const { return fd;}

    virtual bool canRead() const;
    virtual bool canWrite() const;
    virtual bool ioInProgress() const;

private:
    char const *path_;
    RefCount<IORequestor> ioRequestor;
    //RefCount<ReadRequest> readRequest;
    //RefCount<WriteRequest> writeRequest;
    int fd;

    // mmapped memory leads to SEGV and bus errors if it maps beyond file
    int64_t minOffset; ///< enforced if not negative (to preserve file headers)
    int64_t maxOffset; ///< enforced if not negative (to avoid crashes)

    bool error_;

    void doClose();

    CBDATA_CLASS(MmappedFile);
};

#endif /* SQUID_MMAPPEDFILE_H */
