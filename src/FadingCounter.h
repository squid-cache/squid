#ifndef SQUID_FADING_COUNTER_H
#define SQUID_FADING_COUNTER_H

#include "base/Vector.h"

/// Counts events, forgetting old ones. Usefull for "3 errors/minute" limits.
class FadingCounter
{
public:
    FadingCounter();

    /// 0=remember nothing; -1=forget nothing; new value triggers clear()
    void configure(double horizonSeconds);

    void clear(); ///< forgets all events

    int count(int howMany); ///< count fresh, return #events remembered
    int remembered() const { return total; } ///< possibly stale #events

    /// read-only memory horizon in seconds; older events are forgotten
    double horizon;

private:
    const int precision; ///< #counting slots, controls measur. occuracy
    double delta; ///< sub-interval duration = horizon/precision

    double lastTime; ///< time of the last update
    Vector<int> counters; ///< events per delta (possibly stale)
    int total; ///< number of remembered events (possibly stale)
};

#endif /* SQUID_FADING_COUNTER_H */
