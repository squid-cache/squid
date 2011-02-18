#include "config.h"
#include "HelperChildConfig.h"
#include "globals.h"

#include <string.h>

HelperChildConfig::HelperChildConfig(const unsigned int m, const unsigned int s, const unsigned int i, const unsigned int cc) :
        n_max(m),
        n_startup(s),
        n_idle(i),
        concurrency(cc),
        n_running(0),
        n_active(0)
{}

HelperChildConfig::~HelperChildConfig()
{}

HelperChildConfig &
HelperChildConfig::operator =(const HelperChildConfig &rhs)
{
    memcpy(this, &rhs, sizeof(HelperChildConfig));
    return *this;
}

int
HelperChildConfig::needNew() const
{
    /* during the startup and reconfigure use our special amount... */
    if (starting_up || reconfiguring) return n_startup;

    /* keep a minimum of n_idle helpers free... */
    if ( (n_active + n_idle) < n_max) return n_idle;

    /* dont ever start more than n_max processes. */
    return (n_max - n_active);
}

void
HelperChildConfig::parseConfig()
{
    fprintf(stderr, "HelperChildConfig::parseConfig not implemented.");
    exit(1);
}
