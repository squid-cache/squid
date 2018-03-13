/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef COMMANDLINE_H
#define COMMANDLINE_H

#include "sbuf/SBuf.h"
#include <vector>

/// Manages arguments passed to the program, including the program name.
/// The same info is passed to main() as argc and argv[] parameters.
class CommandLine
{
    public:
        // codes for options without short option characters
        enum LongCodes {
            ForegroundCode = 1,
            KidCode = 2
        };

        typedef std::pair<char, SBuf> OptionsPair;
        typedef std::list<OptionsPair> Options;

        CommandLine(int argc, char *argv[]);

        /// \returns parsed kid option argument or an empty string
        SBuf kidName() const;

        /// apply all available command line options
        void processOptions();

        /// generate a new argument list from the parsed one,
        /// supstituting argv[0] and adding/substituting kid option
        const char **argv(const char *argv0, const char *kidName);

        /// \returns Squid executable file name
        SBuf execFile() const { return execFile_; }

    private:
        void processOption(const char, const char *);
        void parse(int argc, char *argv[]);

        SBuf execFile_;
        std::vector<const char *> argv_;
        Options options;
};

#endif

