#include "squid.h"
#include "Debug.h"
#include "adaptation/icap/Client.h"

void Adaptation::Icap::InitModule()
{
    debugs(93,2, HERE << "module enabled.");
}

void Adaptation::Icap::CleanModule()
{
}
