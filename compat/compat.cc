#include "squid.h"
#include "compat.h"

void (*failure_notify) (const char *) = NULL;
