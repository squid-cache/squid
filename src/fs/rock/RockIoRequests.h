#ifndef SQUID_FS_ROCK_IO_REQUESTS_H
#define SQUID_FS_ROCK_IO_REQUESTS_H

#include "DiskIO/ReadRequest.h"
#include "DiskIO/WriteRequest.h"
#include "fs/rock/RockIoState.h"

class DiskFile;

namespace Rock
{

/// \ingroup Rock
class ReadRequest: public ::ReadRequest
{
public:
    ReadRequest(const ::ReadRequest &base, const IoState::Pointer &anSio);
    IoState::Pointer sio;

private:
    CBDATA_CLASS2(ReadRequest);
};

/// \ingroup Rock
class WriteRequest: public ::WriteRequest
{
public:
    WriteRequest(const ::WriteRequest &base, const IoState::Pointer &anSio);
    IoState::Pointer sio;

private:
    CBDATA_CLASS2(WriteRequest);
};

} // namespace Rock

#endif /* SQUID_FS_ROCK_IO_REQUESTS_H */
