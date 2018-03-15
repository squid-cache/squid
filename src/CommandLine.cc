/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "CommandLine.h"

static void
ResetGetopt(const bool allowStderrWarnings)
{
    opterr = allowStderrWarnings ? 1 : 0;
    // getopt(3) uses global state but resets it if optind is zero
    // getopt(3) always skips argv[0], even if optind is zero
    optind = 0;
}

CommandLine::CommandLine(int argC, char *argV[], const char *shortRules, const struct option *longRules):
    argv_(),
    shortOptions_(xstrdup(shortRules)),
    longOptions_()
{
    assert(argC > 0); // C++ main() requirement that makes our arg0() safe

    /* copy argV items */
    argv_.reserve(argC+1);
    for (int i = 0; i < argC; ++i)
        argv_.push_back(xstrdup(argV[i]));
    argv_.push_back(nullptr); // POSIX argv "must be terminated by a null pointer"

    /* copy grammar rules for the long options */
    for (auto longOption = longRules; longOption; ++longOption) {
        longOptions_.push_back(*longOption);
        if (!longOption->name)
            break;
    }
}

CommandLine::CommandLine(const CommandLine &them):
    CommandLine(them.argc(), them.argv(), them.shortOptions_, them.longOptions())
{
}

CommandLine &
CommandLine::operator =(CommandLine them) // not a reference so that we can swap
{
    // cannot just swap(*this, them): std::swap(T,T) may call this assignment op
    std::swap(argv_, them.argv_);
    std::swap(shortOptions_, them.shortOptions_);
    std::swap(longOptions_, them.longOptions_);
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
            if (optValue)
                *optValue = optarg;
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
bool
CommandLine::nextOption(int &optId) const
{
    optId = getopt_long(argc(), argv(), shortOptions_, longOptions(), nullptr);
    // TODO: if (optId == '?'), then throw an error instead of relying on opterr
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
CommandLine::addOption(const char *name, const char *value)
{
    assert(name);
    argv_.push_back(xstrdup(name));
    if (value)
        argv_.push_back(xstrdup(value));
}
