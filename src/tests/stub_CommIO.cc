#include "squid.h"
#include "DiskIO/DiskThreads/CommIO.h"

#define STUB_API "CommIO.cc"
#include "tests/STUB.h"

bool CommIO::Initialised = false;
bool CommIO::DoneSignalled = false;
int CommIO::DoneFD = -1;
int CommIO::DoneReadFD = -1;

void CommIO::ResetNotifications() STUB
void CommIO::Initialise() STUB
void CommIO::NotifyIOClose() STUB
void CommIO::NULLFDHandler(int, void *) STUB
void CommIO::FlushPipe() STUB
