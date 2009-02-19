#include "squid.h"
#include "adaptation/icap/ICAPClient.h"

void ICAPInitModule()
{
    debugs(93,2, "ICAP Client module enabled.");
}

void ICAPCleanModule()
{
}
