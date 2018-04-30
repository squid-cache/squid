/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "CommandLine.h"
#include "sbuf/SBuf.h"

static void
ResetGetopt(const bool allowStderrWarnings)
{
    opterr = allowStderrWarnings;
    // Resetting optind to zero instead of conventional '1' has an
    // advantage, since it also resets getopt(3) global state.
    // getopt(3) always skips argv[0], even if optind is zero
    optind = 0;
}

CommandLine::CommandLine(int argC, char *argV[], const char *shortRules, const RawLongOption *longRules):
    argv_(),
    shortOptions_(shortRules ? xstrdup(shortRules) : ""),
    longOptions_()
{
    assert(argC > 0); // C++ main() requirement that makes our arg0() safe
    assert(shortRules);

    /* copy argV items */
    argv_.reserve(argC+1);
    for (int i = 0; i < argC; ++i)
        argv_.push_back(xstrdup(argV[i]));
    argv_.push_back(nullptr); // POSIX argv "must be terminated by a null pointer"

    /* copy grammar rules for the long options */
    if (longRules) {
        for (auto longOption = longRules; longOption->name; ++longOption)
            longOptions_.emplace_back(*longOption);
        longOptions_.emplace_back();
    }
}

CommandLine::CommandLine(const CommandLine &them):
    CommandLine(them.argc(), them.argv(), them.shortOptions_, them.longOptions())
{
}

CommandLine &
CommandLine::operator =(const CommandLine &them)
{
    // cannot just swap(*this, them): std::swap(T,T) may call this assignment op
    CommandLine tmp(them);
    std::swap(argv_, tmp.argv_);
    std::swap(shortOptions_, tmp.shortOptions_);
    std::swap(longOptions_, tmp.longOptions_);
    return *this;
}

CommandLine::~CommandLine()
{
    for (auto arg: argv_)
        xfree(arg);

    xfree(shortOptions_);
}

bool
CommandLine::hasOption(const int optIdToFind, const char **optValue) const
{
    ResetGetopt(false); // avoid duped warnings; forEachOption() will complain
    int optId = 0;
    while (nextOption(optId)) {
        if (optId == optIdToFind) {
            if (optValue) {
                // do not need to copy the optarg string because it is a pointer into the original
                // argv array (https://www.gnu.org/software/libc/manual/html_node/Using-Getopt.html)
                *optValue = optarg;
            }
            return true;
        }
    }
    return false;
}

void
CommandLine::forEachOption(Visitor visitor) const
{
    ResetGetopt(true);
    int optId = 0;
    while (nextOption(optId))
        visitor(optId, optarg);
}

/// extracts the next option (if any)
/// \returns whether the option was extracted
/// throws on unknown option or missing required argument
bool
CommandLine::nextOption(int &optId) const
{
    optId = getopt_long(argc(), argv(), shortOptions_, longOptions(), nullptr);
    if ((optId == ':' && shortOptions_[0] == ':') || optId == '?') {
        assert(optind > 0 && static_cast<unsigned int>(optind) < argv_.size());
        SBuf errMsg;
        errMsg.Printf("'%s': %s", argv_[optind - 1],  optId == '?' ?
                      "unrecognized option or missing required argument" : "missing required argument");
        throw TexcHere(errMsg);
    }
    return optId != -1;
}

void
CommandLine::resetArg0(const char *programName)
{
    assert(programName);
    xfree(argv_[0]);
    argv_[0] = xstrdup(programName);
}

void
CommandLine::pushFrontOption(const char *name, const char *value)
{
    assert(name);
    argv_.insert(argv_.begin() + 1, xstrdup(name));
    if (value)
        argv_.insert(argv_.begin() + 2, xstrdup(value));
}

LongOption::LongOption() :
    option({nullptr, 0, nullptr, 0})
{
}

LongOption::LongOption(const RawLongOption &opt) :
    option({nullptr, 0, nullptr, 0})
{
    copy(opt);
}

LongOption::LongOption(const LongOption &opt):
    LongOption(static_cast<const RawLongOption &>(opt))
{
}

LongOption::~LongOption()
{
    xfree(name);
}

LongOption &
LongOption::operator =(const LongOption &opt)
{
    if (this != &opt)
        copy(static_cast<const RawLongOption &>(opt));
    return *this;
}

void
LongOption::copy(const RawLongOption &opt)
{
    xfree(name);
    name = opt.name ? xstrdup(opt.name) : nullptr;
    has_arg = opt.has_arg;
    flag = opt.flag;
    val = opt.val;
}

