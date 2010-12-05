#ifndef _PROFILER_GET_TICK_H_
#define _PROFILER_GET_TICK_H_

#if USE_XPROF_STATS

/*
 * Ensure that any changes here are synchronised with SQUID_CHECK_FUNCTIONAL_CPU_PROFILER
 */

#if !_SQUID_SOLARIS_
typedef int64_t  hrtime_t;
#endif

#if defined(__GNUC__) && ( defined(__i386) || defined(__i386__) )
static inline hrtime_t
get_tick(void)
{
    hrtime_t regs;

asm volatile ("rdtsc":"=A" (regs));
    return regs;
    /* We need return value, we rely on CC to optimise out needless subf calls */
    /* Note that "rdtsc" is relatively slow OP and stalls the CPU pipes, so use it wisely */
}

#elif defined(__GNUC__) && ( defined(__x86_64) || defined(__x86_64__) )
static inline hrtime_t
get_tick(void)
{
    uint32_t lo, hi;
    // Based on an example in Wikipedia
    /* We cannot use "=A", since this would use %rax on x86_64 */
asm volatile ("rdtsc" : "=a" (lo), "=d" (hi));
    return (hrtime_t)hi << 32 | lo;
}

#elif defined(__GNUC__) && defined(__alpha)
static inline hrtime_t
get_tick(void)
{
    hrtime_t regs;

asm volatile ("rpcc %0" : "=r" (regs));
    return regs;
}

#elif defined(_M_IX86) && defined(_MSC_VER) /* x86 platform on Microsoft C Compiler ONLY */
static __inline hrtime_t
get_tick(void)
{
    hrtime_t regs;

    __asm {
        cpuid
        rdtsc
        mov eax,DWORD PTR regs[0]
        mov edx,DWORD PTR regs[4]
    }
    return regs;
}

#else
/* This CPU is unsupported. Short-circuit, no profiling here */
// #error for configure tests to prevent library construction
#error This CPU is unsupported. No profiling available here.
#endif

#endif /* USE_XPROF_STATS */
#endif /* _PROFILING_H_ */
