#include "squid.h"
#include "adaptation/icap/Client.h"
#include "Debug.h"

void Adaptation::Icap::InitModule()
{
    debugs(93,2, HERE << "module enabled.");
}

void Adaptation::Icap::CleanModule()
{
}
