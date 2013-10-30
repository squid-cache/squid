#include "squid.h"
#include "SquidTime.h"

#define STUB_API "time.cc"
#include "STUB.h"

struct timeval current_time;
double current_dtime;
time_t squid_curtime = 0;

time_t getCurrentTime(void) STUB
int tvSubMsec(struct timeval, struct timeval) STUB

