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
    char const *token = strtok(NULL, w_space);

    if (!token)
        self_destruct();

    /* starts with a bare number for the max... back-compatible */
    n_max = atoi(token);

    if (n_max < 1)
        self_destruct();

    /* Parse extension options */
    for (; (token = strtok(NULL, w_space)) ;) {
        if (strncmp(token, "startup=", 8) == 0) {
            n_startup = atoi(token + 8);
        } else if (strncmp(token, "idle=", 5) == 0) {
            n_idle = atoi(token + 5);
            if (n_idle < 1) {
                debugs(0,0,"WARNING OVERIDE: Using idle=0 for helpers causes request failures. Overiding to use idle=1 instead.");
                n_idle = 1;
            }
        } else if (strncmp(token, "concurrency=", 12) == 0) {
            concurrency = atoi(token + 12);
        } else {
            self_destruct();
        }
    }

    /* simple sanity. */

    if (n_startup > n_max) {
        debugs(0,0,"WARNING OVERIDE: Capping startup=" << n_startup << " to the defined maximum (" << n_max <<")");
        n_startup = n_max;
    }

    if (n_idle > n_max) {
        debugs(0,0,"WARNING OVERIDE: Capping idle=" << n_idle << " to the defined maximum (" << n_max <<")");
        n_idle = n_max;
    }
}
