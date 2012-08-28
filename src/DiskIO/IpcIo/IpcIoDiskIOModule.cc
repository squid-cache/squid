#include "squid.h"
#include "IpcIoDiskIOModule.h"
#include "IpcIoIOStrategy.h"

IpcIoDiskIOModule::IpcIoDiskIOModule()
{
    ModuleAdd(*this);
}

IpcIoDiskIOModule &
IpcIoDiskIOModule::GetInstance()
{
    return Instance;
}

void
IpcIoDiskIOModule::init()
{}

void
IpcIoDiskIOModule::shutdown()
{}

DiskIOStrategy*
IpcIoDiskIOModule::createStrategy()
{
    return new IpcIoIOStrategy();
}

IpcIoDiskIOModule IpcIoDiskIOModule::Instance;

char const *
IpcIoDiskIOModule::type () const
{
    return "IpcIo";
}
