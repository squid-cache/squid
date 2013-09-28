#include "squid.h"
#include "cache_cf.h"
#include "Debug.h"
#include "HelperChildConfig.h"
#include "globals.h"
#include "Parsing.h"

#include <string.h>

HelperChildConfig::HelperChildConfig(const unsigned int m):
        n_max(m),
        n_startup(0),
        n_idle(1),
        concurrency(0),
        n_running(0),
        n_active(0)
{}

HelperChildConfig &
HelperChildConfig::updateLimits(const HelperChildConfig &rhs)
{
    // Copy the limits only.
    // Preserve the local state values (n_running and n_active)
    n_max = rhs.n_max;
    n_startup = rhs.n_startup;
    n_idle = rhs.n_idle;
    concurrency = rhs.concurrency;
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
    n_max = xatoui(token);

    if (n_max < 1) {
        debugs(0, DBG_CRITICAL, "ERROR: The maximum number of processes cannot be less than 1.");
        self_destruct();
    }

    /* Parse extension options */
    for (; (token = strtok(NULL, w_space)) ;) {
        if (strncmp(token, "startup=", 8) == 0) {
            n_startup = xatoui(token + 8);
        } else if (strncmp(token, "idle=", 5) == 0) {
            n_idle = xatoui(token + 5);
            if (n_idle < 1) {
                debugs(0, DBG_CRITICAL, "WARNING OVERIDE: Using idle=0 for helpers causes request failures. Overiding to use idle=1 instead.");
                n_idle = 1;
            }
        } else if (strncmp(token, "concurrency=", 12) == 0) {
            concurrency = xatoui(token + 12);
        } else {
            debugs(0, DBG_PARSE_NOTE(DBG_IMPORTANT), "ERROR: Undefined option: " << token << ".");
            self_destruct();
        }
    }

    /* simple sanity. */

    if (n_startup > n_max) {
        debugs(0, DBG_CRITICAL, "WARNING OVERIDE: Capping startup=" << n_startup << " to the defined maximum (" << n_max <<")");
        n_startup = n_max;
    }

    if (n_idle > n_max) {
        debugs(0, DBG_CRITICAL, "WARNING OVERIDE: Capping idle=" << n_idle << " to the defined maximum (" << n_max <<")");
        n_idle = n_max;
    }
}
