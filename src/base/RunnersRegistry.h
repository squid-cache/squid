#ifndef SQUID_BASE_RUNNERSREGISTRY_H
#define SQUID_BASE_RUNNERSREGISTRY_H

/**
 * This API allows virtually any module to register with a well-known registry,
 * be activated by some central processor at some registry-specific time, and
 * be deactiveated by some central processor at some registry-specific time.
 *
 * For example, main.cc may activate registered I/O modules after parsing
 * squid.conf and deactivate them before exiting.
 *
 * A module in this context is code providing a functionality or service to the
 * rest of Squid, such as src/DiskIO/Blocking, src/fs/ufs, or Cache Manager. A
 * module must declare a RegisteredRunner child class to implement activation and
 * deactivation logic using the run() method and destructor, respectively.
 *
 * This API allows the registry to determine the right [de]activation time for
 * each group of similar modules, without knowing any module specifics.
 *
 */

/// well-known registries
typedef enum {
    /// Managed by main.cc. Activated after parsing squid.conf and
    /// deactivated before freeing configuration-related memory or exit()-ing.
    /// Meant for setting configuration options that depend on other
    /// configuration options and were not explicitly configured.
    rrFinalizeConfig,

    /// Managed by main.cc. Activated after rrFinalizeConfig and
    /// deactivated before rrFinalizeConfig. Meant for announcing
    /// memory reservations before memory is allocated.
    rrClaimMemoryNeeds,

    /// Managed by main.cc. Activated after rrClaimMemoryNeeds and
    /// deactivated before rrClaimMemoryNeeds. Meant for activating
    /// modules and features based on the finalized configuration.
    rrAfterConfig,

    rrEnd ///< not a real registry, just a label to mark the end of enum
} RunnerRegistry;

/// a runnable registrant API
class RegisteredRunner
{
public:
    // called when this runner's registry is deactivated
    virtual ~RegisteredRunner() {}

    // called when this runner's registry is activated
    virtual void run(const RunnerRegistry &r) = 0;
};

/// registers a given runner with the given registry and returns registry count
int RegisterRunner(const RunnerRegistry &registry, RegisteredRunner *rr);

/// calls run() methods of all runners in the given registry
int ActivateRegistered(const RunnerRegistry &registry);
/// deletes all runners in the given registry
void DeactivateRegistered(const RunnerRegistry &registry);

/// convenience function to "use" an otherwise unreferenced static variable
bool UseThisStatic(const void *);

/// convenience macro: register one RegisteredRunner kid as early as possible
#define RunnerRegistrationEntry(Registry, Who) \
    static const bool Who ## _RegisteredWith_ ## Registry = \
        RegisterRunner(Registry, new Who) > 0 && \
        UseThisStatic(& Who ## _RegisteredWith_ ## Registry);

#endif /* SQUID_BASE_RUNNERSREGISTRY_H */
