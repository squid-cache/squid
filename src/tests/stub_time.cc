#include "squid.h"
#include "SquidTime.h"

#define STUB_API "time.cc"
#include "STUB.h"

struct timeval current_time;
double current_dtime;
time_t squid_curtime = 0;

time_t getCurrentTime(void) STUB
int tvSubMsec(struct timeval, struct timeval) STUB
const char * Time::FormatStrf(time_t ) STUB
const char * Time::FormatHttpd(time_t ) STUB
