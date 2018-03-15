/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_BASE_COMMANDLINE_H /* TODO: Move to src/base/ or remove BASE_. */
#define SQUID_BASE_COMMANDLINE_H

#include <getopt.h>
#include <vector>

/// Manages arguments passed to a program (i.e., main(argc, argv) parameters).
class CommandLine
{
public:
    /// expects main() input plus getopt_long(3) grammar rules for parsing argv
    CommandLine(int argc, char *argv[], const char *shortRules, const struct option *longRules);
    CommandLine(const CommandLine &them);
    ~CommandLine();

    // inefficient profile to simplify implementation
    CommandLine &operator =(CommandLine);

    /// \returns whether the option with optId identifier is present
    /// When returning true, sets non-nil optValue to the found option's value.
    /// For letter options (-x) and their --long synonyms, the letter is the ID.
    /// For long-only --options, the ID is the configured options::val value.
    bool hasOption(const int optId, const char **optValue = nullptr) const;

    /// A callback function for forEachOption(); receives parsed options.
    /// Must not call hasOption() or forEachOption() -- getopt(3) uses globals!
    typedef void Visitor(const int optId, const char *optValue);

    /// calls Visitor for each of the configured command line option
    void forEachOption(Visitor) const;

    /// \returns argv[0], which is usually a program "name"
    const char *arg0() const { return argv_[0]; }

    /// \returns main()'s argc, which is traditionally missing the last/nil item
    int argc() const { return static_cast<int>(argv_.size()) - 1; }

    /// \returns main()'s argv[] which is traditionally const-wrong
    char **argv() const { return const_cast<char**>(argv_.data()); }

    /// replaces argv[0] with the new value
    void resetArg0(const char *programName);

    /// appends a (possibly duplicated) option
    void addOption(const char *name, const char *value = nullptr);

private:
    const struct option *longOptions() const { return longOptions_.size() ? longOptions_.data() : nullptr; }
    bool nextOption(int &optId) const;

    /// raw main() parameters, including argv[0] and a nil argv[argc]
    std::vector<char *> argv_;

    /* getopt_long() grammar rules */
    const char *shortOptions_; ///< single-dash, single-letter (-x) option rules
    std::vector<struct option> longOptions_; ///< long --option rules
};

#endif /* SQUID_BASE_COMMANDLINE_H */
