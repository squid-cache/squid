/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_RUNNERSREGISTRY_H
#define SQUID_BASE_RUNNERSREGISTRY_H

/**
 * This API allows virtually any module to register its interest in receiving
 * notification about initial configuration availability, configuration changes
 * and other critical events in Squid lifetime without exposing the notifier
 * to the details of the module.
 *
 * For example, main.cc may activate registered I/O modules after parsing
 * squid.conf and deactivate them before exiting, all without knowing what
 * those I/O modules really are.
 *
 * A module in this context is code providing a functionality or service to the
 * rest of Squid, such as src/DiskIO/Blocking, src/fs/ufs, or Cache Manager. To
 * receive notifications, a module must declare a RegisteredRunner child class
 * and implement the methods corresponding to the events the module is
 * interested in.
 *
 * The order of events is documented in this header (where applicable), but
 * the order in which runners are notified about a given event is undefined.
 * If a specific notification order is required, split the event into two or
 * more related event(s), documenting their relative order here.
 *
 */

/// a runnable registrant API
/// kids must override [only] the methods they are interested in
class RegisteredRunner
{
public:
    /* Related methods below are declared in their calling order */

    /* Configuration events */

    /// Called after parsing squid.conf.
    /// Meant for setting configuration options that depend on other
    /// configuration options and were not explicitly configured.
    virtual void finalizeConfig() {}

    /// Called after finalizeConfig().
    /// Meant for announcing memory reservations before memory is allocated.
    virtual void claimMemoryNeeds() {}

    /// Called after claimMemoryNeeds().
    /// Meant for activating modules and features using a finalized
    /// configuration with known memory requirements.
    virtual void useConfig() {}

    /* Reconfiguration events */

    /// Called after parsing squid.conf during reconfiguration.
    /// Meant for adjusting the module state based on configuration changes.
    virtual void syncConfig() {}

    /* Shutdown events */

    /// Called after receiving a shutdown request and before stopping the main
    /// loop. At least one main loop iteration is guaranteed after this call.
    /// Meant for cleanup and state saving that may require other modules.
    virtual void startShutdown() {}

    /// Called after shutdown_lifetime grace period ends and before stopping
    /// the main loop. At least one main loop iteration is guaranteed after
    /// this call.
    /// Meant for cleanup and state saving that may require other modules.
    virtual void endingShutdown() {}

    /// Called after stopping the main loop and before releasing memory.
    /// Meant for quick/basic cleanup that does not require any other modules.
    virtual ~RegisteredRunner() {}
    /// exists to simplify caller interface; override the destructor instead
    void finishShutdown() { delete this; }

    /// a pointer to one of the above notification methods
    typedef void (RegisteredRunner::*Method)();

};

/// registers a given runner with the given registry and returns registry count
int RegisterRunner(RegisteredRunner *rr);

/// de-registers a given runner with the given registry and returns registry count
int DeregisterRunner(RegisteredRunner *rr);

/// Calls a given method of all runners.
/// All runners are destroyed after the finishShutdown() call.
void RunRegistered(const RegisteredRunner::Method &m);

/// convenience macro to describe/debug the caller and the method being called
#define RunRegisteredHere(m) \
    debugs(1, 2, "running " # m); \
    RunRegistered(&m)

/// convenience function to "use" an otherwise unreferenced static variable
bool UseThisStatic(const void *);

/// convenience macro: register one RegisteredRunner kid as early as possible
#define RunnerRegistrationEntry(Who) \
    static const bool Who ## _Registered_ = \
        RegisterRunner(new Who) > 0 && \
        UseThisStatic(& Who ## _Registered_);

#endif /* SQUID_BASE_RUNNERSREGISTRY_H */

