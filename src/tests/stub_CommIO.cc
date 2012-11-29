#include "squid.h"
#include "CommIO.h"

bool CommIO::Initialized = false;
bool CommIO::DoneSignalled = false;
int CommIO::DoneFD = -1;
int CommIO::DoneReadFD = -1;

void
CommIO::ResetNotifications()
{
    fatal("Not Implemented");
}

void
CommIO::Initialize()
{
    fatal("Not Implemented");
}

void
CommIO::NotifyIOClose()
{
    fatal("Not Implemented");
}

void
CommIO::NULLFDHandler(int, void *)
{
    fatal("Not Implemented");
}

void
CommIO::FlushPipe()
{
    fatal("Not Implemented");
}
