#include "squid.h"
#include "adaptation/icap/Client.h"

void Adaptation::Icap::InitModule()
{
    debugs(93,2, "ICAP Client module enabled.");
}

void Adaptation::Icap::CleanModule()
{
}
