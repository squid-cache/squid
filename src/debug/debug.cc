/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 00    Debug Routines */

#include "squid.h"
#include "base/TextException.h"
#include "debug/Stream.h"
#include "fatal.h"
#include "fd.h"
#include "ipc/Kids.h"
#include "time/gadgets.h"
#include "util.h"

#include <algorithm>
#include <deque>
#include <functional>
#include <memory>
#include <optional>

char *Debug::debugOptions = nullptr;
int Debug::override_X = 0;
bool Debug::log_syslog = false;
int Debug::Levels[MAX_DEBUG_SECTIONS];
char *Debug::cache_log = nullptr;
int Debug::rotateNumber = -1;

/// a counter related to the number of debugs() calls
using DebugRecordCount = uint64_t;

class DebugModule;

/// Debugging module singleton.
static DebugModule *Module_ = nullptr;

/// Explicitly configured maximum level for debugs() messages written to stderr.
/// debugs() messages with this (or lower) level will be written to stderr (and
/// possibly other channels).
static std::optional<int> ExplicitStderrLevel;

/// ExplicitStderrLevel preference or default: Just like with
/// ExplicitStderrLevel, debugs() messages with this (or lower) level will be
/// written to stderr (and possibly other channels), but this setting is ignored
/// when ExplicitStderrLevel is set. This setting is also ignored after major
/// problems that prevent logging of important debugs() messages (e.g., failing
/// to open cache_log or assertions).
static int DefaultStderrLevel = -1;

/// early debugs() with higher level are not buffered and, hence, may be lost
static constexpr int EarlyMessagesLevel = DBG_IMPORTANT;

/// pre-formatted name of the current process for debugs() messages (or empty)
static std::string ProcessLabel;

static const char *debugLogTime(const timeval &);

#if HAVE_SYSLOG
#ifdef LOG_LOCAL4
static int syslog_facility = 0;
#endif
#endif

#if _SQUID_WINDOWS_
extern LPCRITICAL_SECTION dbg_mutex;
typedef BOOL (WINAPI * PFInitializeCriticalSectionAndSpinCount) (LPCRITICAL_SECTION, DWORD);
#endif

static void ResetSections(const int level = DBG_IMPORTANT);

/// Whether ResetSections() has been called already. We need to keep track of
/// this state because external code may trigger ResetSections() before the
/// DebugModule constructor has a chance to ResetSections() to their defaults.
/// TODO: Find a way to static-initialize Debug::Levels instead.
static bool DidResetSections = false;

/// a named FILE with very-early/late usage safety mechanisms
class DebugFile
{
public:
    DebugFile() {}
    ~DebugFile() { clear(); }
    DebugFile(DebugFile &&) = delete; // no copying or moving of any kind

    /// switches to the new pair, absorbing FILE and duping the name
    void reset(FILE *newFile, const char *newName);

    /// go back to the initial state
    void clear() { reset(nullptr, nullptr); }

    /// an opened cache_log stream or nil
    FILE *file() { return file_; }

    char *name = nullptr;

private:
    friend void ResyncDebugLog(FILE *newFile);

    FILE *file_ = nullptr; ///< opened "real" file or nil; never stderr
};

/// meta-information of a Finish()ed debugs() message
class DebugMessageHeader
{
public:
    DebugMessageHeader(const DebugRecordCount aRecordNumber, const Debug::Context &);

    DebugRecordCount recordNumber; ///< LogMessage() calls before this message
    struct timeval timestamp; ///< approximate debugs() call time
    int section; ///< debugs() section
    int level; ///< debugs() level
    bool forceAlert; ///< debugs() forceAlert flag
};

// Avoid SBuf for CompiledDebugMessageBody:
// * SBuf's own debugging may create a lot of reentrant debugging noise.
// * Debug::Context::buf is an std::string-based STL ostream. Converting its
//   buf() result to a different kind of string may increase complexity/cost.
// TODO: Consider switching to a simple fixed-size buffer and a matching stream!
/// The processed "content" (i.e. the last parameter) part of a debugs() call.
using CompiledDebugMessageBody = std::string;

/// a fully processed debugs(), ready to be logged
class CompiledDebugMessage
{
public:
    using Header = DebugMessageHeader;
    using Body = CompiledDebugMessageBody;

    CompiledDebugMessage(const Header &, const Body &);

    Header header; ///< debugs() meta-information; reflected in log line prefix
    Body body; ///< the log line after the prefix (without the newline)
};

// We avoid PoolingAllocator for CompiledDebugMessages to minimize reentrant
// debugging noise. This noise reduction has negligible performance overhead
// because it only applied to early messages, and there are few of them.
/// debugs() messages captured in LogMessage() call order
using CompiledDebugMessages = std::deque<CompiledDebugMessage>;

/// a receiver of debugs() messages (e.g., stderr or cache.log)
class DebugChannel
{
public:
    using EarlyMessages = std::unique_ptr<CompiledDebugMessages>;

    explicit DebugChannel(const char *aName);
    virtual ~DebugChannel() = default;

    // no copying or moving or any kind (for simplicity sake and to prevent accidental copies)
    DebugChannel(DebugChannel &&) = delete;

    /// whether we are still expecting (and buffering) early messages
    bool collectingEarlyMessages() const { return bool(earlyMessages); }

    /// end early message buffering, logging any saved messages
    void stopEarlyMessageCollection();

    /// end early message buffering, without logging any saved messages
    /// \returns (a possibly empty container with) saved messages or nil
    EarlyMessages releaseEarlyMessages() { return EarlyMessages(earlyMessages.release()); }

    /// Write the message to the channel if the channel accepts (such) messages.
    /// This writing may be delayed until the channel configuration is settled.
    void log(const DebugMessageHeader &, const CompiledDebugMessageBody &);

protected:
    /// output iterator for writing CompiledDebugMessages to a given channel
    class Logger
    {
    public:
        using difference_type = void;
        using value_type = void;
        using pointer = void;
        using reference = void;
        using iterator_category = std::output_iterator_tag;

        explicit Logger(DebugChannel &ch): channel(ch) {}

        Logger &operator=(const CompiledDebugMessage &message)
        {
            if (Debug::Enabled(message.header.section, message.header.level))
                channel.get().log(message.header, message.body);
            return *this;
        }

        // These no-op operators are provided to satisfy LegacyOutputIterator requirements,
        // as is customary for similar STL output iterators like std::ostream_iterator.
        Logger &operator*() { return *this; }
        Logger &operator++() { return *this; }
        Logger &operator++(int) { return *this; }

    private:
        // wrap: output iterators must be CopyAssignable; raw references are not
        std::reference_wrapper<DebugChannel> channel; ///< output destination
    };

    /// whether we should write() the corresponding debugs() message now
    /// (assumes some higher-level code applied cache.log section/level filter)
    virtual bool shouldWrite(const DebugMessageHeader &) const = 0;

    /// write the corresponding debugs() message into the channel
    virtual void write(const DebugMessageHeader &, const CompiledDebugMessageBody &) = 0;

    /// stores the given early message (if possible) or forgets it (otherwise)
    void saveMessage(const DebugMessageHeader &, const CompiledDebugMessageBody &);

    /// stop saving and log() any "early" messages, in recordNumber order
    static void StopSavingAndLog(DebugChannel &, DebugChannel * = nullptr);

    /// Formats a validated debugs() record and writes it to the given FILE.
    void writeToStream(FILE &, const DebugMessageHeader &, const CompiledDebugMessageBody &);

    /// reacts to a written a debugs() message
    void noteWritten(const DebugMessageHeader &);

protected:
    const char * const name = nullptr; ///< unique channel label for debugging

    /// the number of messages sent to the underlying channel so far
    DebugRecordCount written = 0;

    /// DebugMessageHeader::recordNumber of the last message we wrote
    DebugRecordCount lastWrittenRecordNumber = 0;

    /// debugs() messages waiting for the channel configuration to settle (and
    /// the channel to open) so that their eligibility for logging can be
    /// determined (and the messages can be actually written somewhere)
    EarlyMessages earlyMessages;
};

/// DebugChannel managing messages destined for the configured cache_log file
class CacheLogChannel: public DebugChannel
{
public:
    CacheLogChannel(): DebugChannel("cache_log") {}

protected:
    /* DebugChannel API */
    bool shouldWrite(const DebugMessageHeader &) const final;
    void write(const DebugMessageHeader &, const CompiledDebugMessageBody &) final;
};

/// DebugChannel managing messages destined for "standard error stream" (stderr)
class StderrChannel: public DebugChannel
{
public:
    StderrChannel(): DebugChannel("stderr") {}

    /// start to take care of past/saved and future cacheLovirtual gChannel messages
    void takeOver(CacheLogChannel &);

    /// stop providing a cache_log replacement (if we were providing it)
    void stopCoveringForCacheLog();

    /// \copydoc DebugChannel::shouldWrite()
    bool enabled(const int messageDebugLevel) const;

protected:
    /* DebugChannel API */
    bool shouldWrite(const DebugMessageHeader &) const final;
    void write(const DebugMessageHeader &, const CompiledDebugMessageBody &) final;

private:
    /// whether we are the last resort for logging debugs() messages
    bool coveringForCacheLog = false;
};

/// syslog DebugChannel
class SyslogChannel: public DebugChannel
{
public:
    SyslogChannel(): DebugChannel("syslog") {}

    void markOpened() { opened = true; }

protected:
    /* DebugChannel API */
    bool shouldWrite(const DebugMessageHeader &) const final;
    void write(const DebugMessageHeader &, const CompiledDebugMessageBody &) final;

private:
    bool opened = false; ///< whether openlog() was called
};

/// Manages private module state that must be available during program startup
/// and (especially) termination. Any non-trivial state objects must be
/// encapsulated here because debugs() may be called before dynamic
/// initialization or after the destruction of static objects in debug.cc.
class DebugModule
{
public:
    DebugModule();

    // we provide debugging services for the entire duration of the program
    ~DebugModule() = delete;

    /// \copydoc Debug::PrepareToDie()
    void prepareToDie();

    /// Log the given debugs() message to appropriate channel(s) (eventually).
    /// Assumes the message has passed the global section/level filter.
    void log(const DebugMessageHeader &, const CompiledDebugMessageBody &);

    /// Start using an open cache_log file as the primary debugs() destination.
    /// Stop using stderr as a cache_log replacement (if we were doing that).
    void useCacheLog();

    /// Start using stderr as the primary debugs() destination.
    /// Stop waiting for an open cache_log file (if we were doing that).
    void banCacheLogUse();

public:
    CacheLogChannel cacheLogChannel;
    StderrChannel stderrChannel;
    SyslogChannel syslogChannel;
};

/// Maintains the number of code paths on the current call stack that need
/// protection from new debugs() calls. Squid cannot _block_ re-entrant debugs()
/// calls, but the high-level debugs() handling code queues re-entrant logging
/// attempts when Busy() instead of letting them through to sensitive code.
class LoggingSectionGuard
{
public:
    LoggingSectionGuard();
    ~LoggingSectionGuard();

    /// whether new debugs() messages must be queued
    static bool Busy() { return LoggingConcurrencyLevel; }

private:
    /// the current number of protected callers
    static size_t LoggingConcurrencyLevel;
};

size_t LoggingSectionGuard::LoggingConcurrencyLevel = 0;

/// debugs() messages postponed due to LoggingSectionGuard::Busy(). This is the
/// head of the invasive Context::upper FIFO list of such messages.
static Debug::Context *WaitingForIdle = nullptr;

/// cache_log file
/// safe during static initialization, even if it has not been constructed yet
/// safe during program termination, even if it has been destructed already
static DebugFile TheLog;

FILE *
DebugStream() {
    return TheLog.file() ? TheLog.file() : stderr;
}

/// used for the side effect: fills Debug::Levels with the given level
static void
ResetSections(const int level)
{
    DidResetSections = true;
    for (auto &sectionLevel: Debug::Levels)
        sectionLevel = level;
}

/// optimization: formats ProcessLabel once for frequent debugs() reuse
static void
LabelThisProcess(const char * const name, const std::optional<int> id = std::optional<int>())
{
    assert(name);
    assert(strlen(name));
    std::stringstream os;
    os << ' ' << name;
    if (id.has_value()) {
        assert(id.value() >= 0);
        os << id.value();
    }
    ProcessLabel = os.str();
}

void
Debug::NameThisHelper(const char * const name)
{
    LabelThisProcess(name);

    if (const auto parentProcessDebugOptions = getenv("SQUID_DEBUG")) {
        assert(!debugOptions);
        debugOptions = xstrdup(parentProcessDebugOptions);
    }

    // do not restrict helper (i.e. stderr) logging beyond debug_options
    EnsureDefaultStderrLevel(DBG_DATA);

    // helpers do not write to cache.log directly; instead, ipcCreate()
    // diverts helper stderr output to cache.log of the parent process
    BanCacheLogUse();

    SettleStderr();
    SettleSyslog();

    debugs(84, 2, "starting " << name << " with PID " << getpid());
}

void
Debug::NameThisKid(const int kidIdentifier)
{
    // to reduce noise and for backward compatibility, do not label kid messages
    // in non-SMP mode
    if (kidIdentifier)
        LabelThisProcess("kid", std::optional<int>(kidIdentifier));
    else
        ProcessLabel.clear(); // probably already empty
}

/* LoggingSectionGuard */

LoggingSectionGuard::LoggingSectionGuard()
{
    ++LoggingConcurrencyLevel;
}

LoggingSectionGuard::~LoggingSectionGuard()
{
    if (--LoggingConcurrencyLevel == 0)
        Debug::LogWaitingForIdle();
}

/* DebugModule */

// Depending on DBG_CRITICAL activity and command line options, this code may
// run as early as static initialization during program startup or as late as
// the first debugs(DBG_CRITICAL) call from the main loop.
DebugModule::DebugModule()
{
    // explicit initialization before any use by debugs() calls; see bug #2656
    tzset();

    (void)std::atexit(&Debug::PrepareToDie);

    if (!DidResetSections)
        ResetSections();
}

void
DebugModule::log(const DebugMessageHeader &header, const CompiledDebugMessageBody &body)
{
    cacheLogChannel.log(header, body);
    stderrChannel.log(header, body);
    syslogChannel.log(header, body);
}

void
DebugModule::prepareToDie()
{
    const LoggingSectionGuard sectionGuard;

    // Switch to stderr to improve our chances to log _early_ debugs(). However,
    // use existing cache_log and/or stderr levels for post-open/close ones.
    if (cacheLogChannel.collectingEarlyMessages() && !TheLog.file())
        banCacheLogUse();

    cacheLogChannel.stopEarlyMessageCollection();
    stderrChannel.stopEarlyMessageCollection();
    syslogChannel.stopEarlyMessageCollection();

    // Explicit last-resort call because we want to dump any pending messages
    // (possibly including an assertion) even if another call, higher in the
    // call stack, is currently in the sensitive section. Squid is dying, and
    // that other caller (if any) will not get control back and, hence, will not
    // trigger a Debug::LogWaitingForIdle() check. In most cases, we will log
    // any pending messages successfully here. In the remaining few cases, we
    // will lose them just like we would lose them without this call. The
    // (small) risk here is that we might abort() or crash trying.
    Debug::LogWaitingForIdle();

    // Do not close/destroy channels: While the Debug module is not _guaranteed_
    // to get control after prepareToDie(), debugs() calls are still very much
    // _possible_, and we want to support/log them for as long as we can.
}

void
DebugModule::useCacheLog()
{
    assert(TheLog.file());
    stderrChannel.stopCoveringForCacheLog(); // in case it was covering
    cacheLogChannel.stopEarlyMessageCollection(); // in case it was collecting
}

void
DebugModule::banCacheLogUse()
{
    assert(!TheLog.file());
    stderrChannel.takeOver(cacheLogChannel);
}

/// safe access to the debugging module
static
DebugModule &
Module()
{
    if (!Module_) {
        Module_ = new DebugModule();
#if !HAVE_SYSLOG
        // Optimization: Do not wait for others to tell us what we already know.
        Debug::SettleSyslog();
#endif
    }

    return *Module_;
}

void
ResyncDebugLog(FILE *newFile)
{
    TheLog.file_ = newFile;
}

/* DebugChannel */

DebugChannel::DebugChannel(const char * const aName):
    name(aName),
    earlyMessages(new CompiledDebugMessages())
{
}

void
DebugChannel::stopEarlyMessageCollection()
{
    if (earlyMessages)
        StopSavingAndLog(*this);
    // else already stopped
}

void
DebugChannel::log(const DebugMessageHeader &header, const CompiledDebugMessageBody &body)
{
    if (header.recordNumber <= lastWrittenRecordNumber)
        return;

    if (!shouldWrite(header))
        return saveMessage(header, body);

    // We only save messages until we learn whether the channel is going to be
    // used. We now know that it will be used. Also logs saved early messages
    // (if they became eligible now) before lastWrittenRecordNumber blocks them.
    stopEarlyMessageCollection();

    write(header, body);
}

void
Debug::ForgetSaved()
{
    auto &module = Module();
    (void)module.cacheLogChannel.releaseEarlyMessages();
    (void)module.stderrChannel.releaseEarlyMessages();
    (void)module.syslogChannel.releaseEarlyMessages();
}

void
Debug::PrepareToDie()
{
    Module().prepareToDie();
}

void
DebugChannel::StopSavingAndLog(DebugChannel &channelA, DebugChannel *channelBOrNil)
{
    const LoggingSectionGuard sectionGuard;

    assert(&channelA != channelBOrNil);
    const auto asOrNil = channelA.releaseEarlyMessages();
    const auto bsOrNil = channelBOrNil ? channelBOrNil->releaseEarlyMessages() : nullptr;
    const auto &as = asOrNil ? *asOrNil : CompiledDebugMessages();
    const auto &bs = bsOrNil ? *bsOrNil : CompiledDebugMessages();

    const auto writtenEarlier = channelA.written;

    std::merge(as.begin(), as.end(), bs.begin(), bs.end(), Logger(channelA),
    [](const CompiledDebugMessage &mA, const CompiledDebugMessage &mB) {
        return mA.header.recordNumber < mB.header.recordNumber;
    });

    const auto writtenNow = channelA.written - writtenEarlier;
    if (const auto totalCount = as.size() + bs.size()) {
        debugs(0, 5, "wrote " << writtenNow << " out of " << totalCount << '=' <<
               as.size() << '+' << bs.size() << " early messages to " << channelA.name);
    }
}

void
DebugChannel::saveMessage(const DebugMessageHeader &header, const CompiledDebugMessageBody &body)
{
    if (!earlyMessages)
        return; // we have stopped saving early messages

    if (header.level > EarlyMessagesLevel)
        return; // this message is not important enough to save

    // Given small EarlyMessagesLevel, only a Squid bug can cause so many
    // earlyMessages. Saving/dumping excessive messages correctly is not only
    // difficult but is more likely to complicate triage than help: It is the
    // first earlyMessages that are going to be the most valuable. Our assert()
    // will dump them if at all possible.
    assert(earlyMessages->size() < 1000);

    earlyMessages->emplace_back(header, body);
}

void
DebugChannel::writeToStream(FILE &destination, const DebugMessageHeader &header, const CompiledDebugMessageBody &body)
{
    fprintf(&destination, "%s%s| %s\n",
            debugLogTime(header.timestamp),
            ProcessLabel.c_str(),
            body.c_str());
    noteWritten(header);
}

void
DebugChannel::noteWritten(const DebugMessageHeader &header)
{
    ++written;
    lastWrittenRecordNumber = header.recordNumber;
}

/* CacheLogChannel */

bool
CacheLogChannel::shouldWrite(const DebugMessageHeader &) const
{
    return TheLog.file();
}

void
CacheLogChannel::write(const DebugMessageHeader &header, const CompiledDebugMessageBody &body)
{
    writeToStream(*TheLog.file(), header, body);
    fflush(TheLog.file());
}

/* StderrChannel */

bool
StderrChannel::enabled(const int level) const
{
    if (!stderr)
        return false; // nowhere to write

    if (ExplicitStderrLevel.has_value()) // explicit admin restrictions (-d)
        return level <= ExplicitStderrLevel.value();

    // whether the given level is allowed by emergency handling circumstances
    // (coveringForCacheLog) or configuration aspects (e.g., -k or -z)
    return coveringForCacheLog || level <= DefaultStderrLevel;
}

bool
StderrChannel::shouldWrite(const DebugMessageHeader &header) const
{
    return enabled(header.level);
}

void
StderrChannel::write(const DebugMessageHeader &header, const CompiledDebugMessageBody &body)
{
    writeToStream(*stderr, header, body);
}

void
StderrChannel::takeOver(CacheLogChannel &cacheLogChannel)
{
    if (coveringForCacheLog)
        return;
    coveringForCacheLog = true;

    StopSavingAndLog(*this, &cacheLogChannel);
}

void
StderrChannel::stopCoveringForCacheLog()
{
    if (!coveringForCacheLog)
        return;

    coveringForCacheLog = false;
    debugs(0, DBG_IMPORTANT, "Resuming logging to cache_log");
}

void
Debug::EnsureDefaultStderrLevel(const int maxDefault)
{
    if (DefaultStderrLevel < maxDefault)
        DefaultStderrLevel = maxDefault; // may set or increase
    // else: somebody has already requested a more permissive maximum
}

void
Debug::ResetStderrLevel(const int maxLevel)
{
    ExplicitStderrLevel = maxLevel; // may set, increase, or decrease
}

void
Debug::SettleStderr()
{
    auto &stderrChannel = Module().stderrChannel;

    stderrChannel.stopEarlyMessageCollection();

    if (override_X) {
        // Some users might expect -X to force -d9. Tell them what is happening.
        const auto outcome =
            stderrChannel.enabled(DBG_DATA) ? "; stderr will see all messages":
            stderrChannel.enabled(DBG_CRITICAL) ? "; stderr will not see some messages":
            "; stderr will see no messages";
        if (ExplicitStderrLevel)
            debugs(0, DBG_CRITICAL, "Using -X and -d" << ExplicitStderrLevel.value() << outcome);
        else
            debugs(0, DBG_CRITICAL, "Using -X without -d" << outcome);
    }
}

bool
Debug::StderrEnabled()
{
    return Module().stderrChannel.enabled(DBG_CRITICAL);
}

/* DebugMessageHeader */

DebugMessageHeader::DebugMessageHeader(const DebugRecordCount aRecordNumber, const Debug::Context &context):
    recordNumber(aRecordNumber),
    section(context.section),
    level(context.level),
    forceAlert(context.forceAlert)
{
    (void)getCurrentTime(); // update current_time
    timestamp = current_time;
}

/* CompiledDebugMessage */

CompiledDebugMessage::CompiledDebugMessage(const Header &aHeader, const Body &aBody):
    header(aHeader),
    body(aBody)
{
}

/* DebugFile */

void
DebugFile::reset(FILE *newFile, const char *newName)
{
    // callers must use nullptr instead of the used-as-the-last-resort stderr
    assert(newFile != stderr || !stderr);

    if (file_) {
        fd_close(fileno(file_));
        fclose(file_);
    }
    file_ = newFile; // may be nil

    if (file_)
        fd_open(fileno(file_), FD_LOG, Debug::cache_log);

    xfree(name);
    name = newName ? xstrdup(newName) : nullptr;

    // all open files must have a name
    // all cleared files must not have a name
    assert(!file_ == !name);
}

/// broadcasts debugs() message to the logging channels
void
Debug::LogMessage(const Context &context)
{
#if _SQUID_WINDOWS_
    /* Multiple WIN32 threads may call this simultaneously */

    if (!dbg_mutex) {
        HMODULE krnl_lib = GetModuleHandle("Kernel32");
        PFInitializeCriticalSectionAndSpinCount InitializeCriticalSectionAndSpinCount = nullptr;

        if (krnl_lib)
            InitializeCriticalSectionAndSpinCount =
                (PFInitializeCriticalSectionAndSpinCount) GetProcAddress(krnl_lib,
                        "InitializeCriticalSectionAndSpinCount");

        dbg_mutex = static_cast<CRITICAL_SECTION*>(xcalloc(1, sizeof(CRITICAL_SECTION)));

        if (InitializeCriticalSectionAndSpinCount) {
            /* let multiprocessor systems EnterCriticalSection() fast */

            if (!InitializeCriticalSectionAndSpinCount(dbg_mutex, 4000)) {
                if (const auto logFile = TheLog.file()) {
                    fprintf(logFile, "FATAL: %s: can't initialize critical section\n", __FUNCTION__);
                    fflush(logFile);
                }

                fprintf(stderr, "FATAL: %s: can't initialize critical section\n", __FUNCTION__);
                abort();
            } else
                InitializeCriticalSection(dbg_mutex);
        }
    }

    EnterCriticalSection(dbg_mutex);
#endif

    static DebugRecordCount LogMessageCalls = 0;
    const DebugMessageHeader header(++LogMessageCalls, context);
    Module().log(header, context.buf.str());

#if _SQUID_WINDOWS_
    LeaveCriticalSection(dbg_mutex);
#endif
}

static void
debugArg(const char *arg)
{
    int s = 0;
    int l = 0;

    if (!strncasecmp(arg, "rotate=", 7)) {
        arg += 7;
        Debug::rotateNumber = atoi(arg);
        return;
    } else if (!strncasecmp(arg, "ALL", 3)) {
        s = -1;
        arg += 4;
    } else {
        s = atoi(arg);
        while (*arg && *arg++ != ',');
    }

    l = atoi(arg);
    assert(s >= -1);

    if (s >= MAX_DEBUG_SECTIONS)
        s = MAX_DEBUG_SECTIONS-1;

    if (l < 0)
        l = 0;

    if (l > 10)
        l = 10;

    if (s >= 0) {
        Debug::Levels[s] = l;
        return;
    }

    ResetSections(l);
}

static void
debugOpenLog(const char *logfile)
{
    assert(logfile);

    // Bug 4423: ignore the stdio: logging module name if present
    const char *logfilename;
    if (strncmp(logfile, "stdio:",6) == 0)
        logfilename = logfile + 6;
    else
        logfilename = logfile;

    if (auto log = fopen(logfilename, "a+")) {
#if _SQUID_WINDOWS_
        setmode(fileno(log), O_TEXT);
#endif
        TheLog.reset(log, logfilename);
        Module().useCacheLog();
    } else {
        const auto xerrno = errno;
        TheLog.clear();
        Module().banCacheLogUse();

        // report the problem after banCacheLogUse() to improve our chances of
        // reporting earlier debugs() messages (that cannot be written after us)
        debugs(0, DBG_CRITICAL, "ERROR: Cannot open cache_log (" << logfilename << ") for writing;" <<
               Debug::Extra << "fopen(3) error: " << xstrerr(xerrno));
    }
}

#if HAVE_SYSLOG
#ifdef LOG_LOCAL4

static struct syslog_facility_name {
    const char *name;
    int facility;
}

syslog_facility_names[] = {

#ifdef LOG_AUTH
    {
        "auth", LOG_AUTH
    },
#endif
#ifdef LOG_AUTHPRIV
    {
        "authpriv", LOG_AUTHPRIV
    },
#endif
#ifdef LOG_CRON
    {
        "cron", LOG_CRON
    },
#endif
#ifdef LOG_DAEMON
    {
        "daemon", LOG_DAEMON
    },
#endif
#ifdef LOG_FTP
    {
        "ftp", LOG_FTP
    },
#endif
#ifdef LOG_KERN
    {
        "kern", LOG_KERN
    },
#endif
#ifdef LOG_LPR
    {
        "lpr", LOG_LPR
    },
#endif
#ifdef LOG_MAIL
    {
        "mail", LOG_MAIL
    },
#endif
#ifdef LOG_NEWS
    {
        "news", LOG_NEWS
    },
#endif
#ifdef LOG_SYSLOG
    {
        "syslog", LOG_SYSLOG
    },
#endif
#ifdef LOG_USER
    {
        "user", LOG_USER
    },
#endif
#ifdef LOG_UUCP
    {
        "uucp", LOG_UUCP
    },
#endif
#ifdef LOG_LOCAL0
    {
        "local0", LOG_LOCAL0
    },
#endif
#ifdef LOG_LOCAL1
    {
        "local1", LOG_LOCAL1
    },
#endif
#ifdef LOG_LOCAL2
    {
        "local2", LOG_LOCAL2
    },
#endif
#ifdef LOG_LOCAL3
    {
        "local3", LOG_LOCAL3
    },
#endif
#ifdef LOG_LOCAL4
    {
        "local4", LOG_LOCAL4
    },
#endif
#ifdef LOG_LOCAL5
    {
        "local5", LOG_LOCAL5
    },
#endif
#ifdef LOG_LOCAL6
    {
        "local6", LOG_LOCAL6
    },
#endif
#ifdef LOG_LOCAL7
    {
        "local7", LOG_LOCAL7
    },
#endif
    {
        nullptr, 0
    }
};

#endif

static void
_db_set_syslog(const char *facility)
{
    Debug::log_syslog = true;

#ifdef LOG_LOCAL4
#ifdef LOG_DAEMON

    syslog_facility = LOG_DAEMON;
#else

    syslog_facility = LOG_LOCAL4;
#endif /* LOG_DAEMON */

    if (facility) {

        struct syslog_facility_name *n;

        for (n = syslog_facility_names; n->name; ++n) {
            if (strcmp(n->name, facility) == 0) {
                syslog_facility = n->facility;
                return;
            }
        }

        fprintf(stderr, "unknown syslog facility '%s'\n", facility);
        exit(EXIT_FAILURE);
    }

#else
    if (facility)
        fprintf(stderr, "syslog facility type not supported on your system\n");

#endif /* LOG_LOCAL4 */
}

/* SyslogChannel */

static int
SyslogPriority(const DebugMessageHeader &header)
{
    return header.forceAlert ? LOG_ALERT :
           (header.level == 0 ? LOG_WARNING : LOG_NOTICE);
}

void
SyslogChannel::write(const DebugMessageHeader &header, const CompiledDebugMessageBody &body)
{
    syslog(SyslogPriority(header), "%s", body.c_str());
    noteWritten(header);
}

#else

void
SyslogChannel::write(const DebugMessageHeader &, const CompiledDebugMessageBody &)
{
    assert(!"unreachable code because opened, shouldWrite() are always false");
}

#endif /* HAVE_SYSLOG */

bool
SyslogChannel::shouldWrite(const DebugMessageHeader &header) const
{
    if (!opened)
        return false;

    assert(Debug::log_syslog);
    return header.forceAlert || header.level <= DBG_IMPORTANT;
}

void
Debug::ConfigureSyslog(const char *facility)
{
#if HAVE_SYSLOG
    _db_set_syslog(facility);
#else
    (void)facility;
    // TODO: Throw.
    fatalf("Logging to syslog not available on this platform");
#endif
}

void
Debug::parseOptions(char const *options)
{
    char *p = nullptr;
    char *s = nullptr;

    if (override_X) {
        debugs(0, 9, "command-line -X overrides: " << options);
        return;
    }

    ResetSections();

    if (options) {
        p = xstrdup(options);

        for (s = strtok(p, w_space); s; s = strtok(nullptr, w_space))
            debugArg(s);

        xfree(p);
    }
}

void
Debug::BanCacheLogUse()
{
    Debug::parseOptions(debugOptions);
    Module().banCacheLogUse();
}

void
Debug::UseCacheLog()
{
    Debug::parseOptions(debugOptions);
    debugOpenLog(cache_log);
}

void
Debug::StopCacheLogUse()
{
    if (TheLog.file()) {
        // UseCacheLog() was successful.
        Module().cacheLogChannel.stopEarlyMessageCollection(); // paranoid
        TheLog.clear();
    } else {
        // UseCacheLog() was not called at all or failed to open cache_log.
        Module().banCacheLogUse(); // may already be banned
    }
}

void
Debug::SettleSyslog()
{
#if HAVE_SYSLOG && defined(LOG_LOCAL4)

    if (Debug::log_syslog) {
        openlog(APP_SHORTNAME, LOG_PID | LOG_NDELAY | LOG_CONS, syslog_facility);
        Module().syslogChannel.markOpened();
    }

#endif /* HAVE_SYSLOG */

    Module().syslogChannel.stopEarlyMessageCollection();
}

void
_db_rotate_log(void)
{
    if (!TheLog.name)
        return;

#ifdef S_ISREG
    struct stat sb;
    if (stat(TheLog.name, &sb) == 0)
        if (S_ISREG(sb.st_mode) == 0)
            return;
#endif

    char from[MAXPATHLEN];
    from[0] = '\0';

    char to[MAXPATHLEN];
    to[0] = '\0';

    /*
     * NOTE: we cannot use xrename here without having it in a
     * separate file -- tools.c has too many dependencies to be
     * used everywhere debug.c is used.
     */
    /* Rotate numbers 0 through N up one */
    for (int i = Debug::rotateNumber; i > 1;) {
        --i;
        snprintf(from, MAXPATHLEN, "%s.%d", TheLog.name, i - 1);
        snprintf(to, MAXPATHLEN, "%s.%d", TheLog.name, i);
#if _SQUID_WINDOWS_
        remove
        (to);
#endif
        errno = 0;
        if (rename(from, to) == -1) {
            const auto saved_errno = errno;
            debugs(0, DBG_IMPORTANT, "ERROR: log rotation failed: " << xstrerr(saved_errno));
        }
    }

    /* Rotate the current log to .0 */
    if (Debug::rotateNumber > 0) {
        // form file names before we may clear TheLog below
        snprintf(from, MAXPATHLEN, "%s", TheLog.name);
        snprintf(to, MAXPATHLEN, "%s.%d", TheLog.name, 0);

#if _SQUID_WINDOWS_
        errno = 0;
        if (remove(to) == -1) {
            const auto saved_errno = errno;
            debugs(0, DBG_IMPORTANT, "ERROR: removal of log file " << to << " failed: " << xstrerr(saved_errno));
        }
        TheLog.clear(); // Windows cannot rename() open files
#endif
        errno = 0;
        if (rename(from, to) == -1) {
            const auto saved_errno = errno;
            debugs(0, DBG_IMPORTANT, "ERROR: renaming file " << from << " to "
                   << to << "failed: " << xstrerr(saved_errno));
        }
    }

    // Close (if we have not already) and reopen the log because
    // it may have been renamed "manually" before HUP'ing us.
    debugOpenLog(Debug::cache_log);
}

static const char *
debugLogTime(const timeval &t)
{
    static char buf[128]; // arbitrary size, big enough for the below timestamp strings.
    static time_t last_t = 0;

    if (Debug::Level() > 1) {
        last_t = t.tv_sec;
        // 4 bytes smaller than buf to ensure .NNN catenation by snprintf()
        // is safe and works even if strftime() fills its buffer.
        char buf2[sizeof(buf)-4];
        const auto tm = localtime(&last_t);
        strftime(buf2, sizeof(buf2), "%Y/%m/%d %H:%M:%S", tm);
        buf2[sizeof(buf2)-1] = '\0';
        const auto sz = snprintf(buf, sizeof(buf), "%s.%03d", buf2, static_cast<int>(t.tv_usec / 1000));
        assert(0 < sz && sz < static_cast<int>(sizeof(buf)));
        // force buf reset for subsequent level-0/1 messages that should have no milliseconds
        last_t = 0;
    } else if (t.tv_sec != last_t) {
        last_t = t.tv_sec;
        const auto tm = localtime(&last_t);
        const int sz = strftime(buf, sizeof(buf), "%Y/%m/%d %H:%M:%S", tm);
        assert(0 < sz && sz <= static_cast<int>(sizeof(buf)));
    }

    buf[sizeof(buf)-1] = '\0';
    return buf;
}

/// Whether there are any xassert() calls in the call stack. Treat as private to
/// xassert(): It is moved out only to simplify the asserting code path.
static auto Asserting_ = false;

void
xassert(const char *msg, const char *file, int line)
{
    // if the non-trivial code below has itself asserted, then simplify instead
    // of running out of stack and complicating triage
    if (Asserting_)
        abort();

    Asserting_ = true;

    debugs(0, DBG_CRITICAL, "FATAL: assertion failed: " << file << ":" << line << ": \"" << msg << "\"");

    Debug::PrepareToDie();
    abort();
}

Debug::Context *Debug::Current = nullptr;

Debug::Context::Context(const int aSection, const int aLevel):
    section(aSection),
    level(aLevel),
    sectionLevel(Levels[aSection]),
    upper(Current),
    forceAlert(false),
    waitingForIdle(false)
{
    formatStream();
}

/// Optimization: avoids new Context creation for every debugs().
void
Debug::Context::rewind(const int aSection, const int aLevel)
{
    section = aSection;
    level = aLevel;
    sectionLevel = Levels[aSection];
    assert(upper == Current);
    assert(!waitingForIdle);

    buf.str(CompiledDebugMessageBody());
    buf.clear();
    // debugs() users are supposed to preserve format, but
    // some do not, so we have to waste cycles resetting it for all.
    formatStream();
}

/// configures default formatting for the debugging stream
void
Debug::Context::formatStream()
{
    const static std::ostringstream cleanStream;
    buf.flags(cleanStream.flags() | std::ios::fixed);
    buf.width(cleanStream.width());
    buf.precision(2);
    buf.fill(' ');
    // If this is not enough, use copyfmt(cleanStream) which is ~10% slower.
}

void
Debug::LogWaitingForIdle()
{
    if (!WaitingForIdle)
        return; // do not lock in vain because unlocking would calls us

    const LoggingSectionGuard sectionGuard;
    while (const auto current = WaitingForIdle) {
        assert(current->waitingForIdle);
        LogMessage(*current);
        WaitingForIdle = current->upper;
        delete current;
    }
}

std::ostringstream &
Debug::Start(const int section, const int level)
{
    Context *future = nullptr;

    if (LoggingSectionGuard::Busy()) {
        // a very rare reentrant debugs() call that originated during Finish() and such
        future = new Context(section, level);
        future->waitingForIdle = true;
    } else if (Current) {
        // a rare reentrant debugs() call that originated between Start() and Finish()
        future = new Context(section, level);
    } else {
        // Optimization: Nearly all debugs() calls get here; avoid allocations
        static Context *topContext = new Context(1, 1);
        topContext->rewind(section, level);
        future = topContext;
    }

    Current = future;

    return future->buf;
}

void
Debug::Finish()
{
    const LoggingSectionGuard sectionGuard;

    // TODO: #include "base/CodeContext.h" instead if doing so works well.
    extern std::ostream &CurrentCodeContextDetail(std::ostream &os);
    if (Current->level <= DBG_IMPORTANT)
        Current->buf << CurrentCodeContextDetail;

    if (Current->waitingForIdle) {
        const auto past = Current;
        Current = past->upper;
        past->upper = nullptr;
        // do not delete `past` because we store it in WaitingForIdle below

        // waitingForIdle messages are queued here instead of Start() because
        // their correct order is determined by the Finish() call timing/order.
        // Linear search, but this list ought to be very short (usually empty).
        auto *last = &WaitingForIdle;
        while (*last)
            last = &(*last)->upper;
        *last = past;

        return;
    }

    LogMessage(*Current);
    Current->forceAlert = false;

    Context *past = Current;
    Current = past->upper;
    if (Current)
        delete past;
    // else it was a static topContext from Debug::Start()
}

void
Debug::ForceAlert()
{
    //  the ForceAlert(ostream) manipulator should only be used inside debugs()
    if (Current)
        Current->forceAlert = true;
}

std::ostream&
ForceAlert(std::ostream& s)
{
    Debug::ForceAlert();
    return s;
}

