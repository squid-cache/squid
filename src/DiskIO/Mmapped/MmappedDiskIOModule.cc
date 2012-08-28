#include "squid.h"
#include "MmappedDiskIOModule.h"
#include "MmappedIOStrategy.h"

MmappedDiskIOModule::MmappedDiskIOModule()
{
    ModuleAdd(*this);
}

MmappedDiskIOModule &
MmappedDiskIOModule::GetInstance()
{
    return Instance;
}

void
MmappedDiskIOModule::init()
{}

void
MmappedDiskIOModule::shutdown()
{}

DiskIOStrategy*
MmappedDiskIOModule::createStrategy()
{
    return new MmappedIOStrategy();
}

MmappedDiskIOModule MmappedDiskIOModule::Instance;

char const *
MmappedDiskIOModule::type () const
{
    return "Mmapped";
}
