/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * Copyright (c) 2009-2014, Treehouse Networks Ltd. New Zealand
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Fake Basic Authentication program for Squid.
 *
 * This code gets the user details and returns OK.
 * It is intended for testing use and as a base for further implementation.
 */

#include "squid.h"
#include "helper/protocol_defines.h"

#include <iostream>
#include <string>

/**
 * options:
 * -d enable debugging.
 * -h interface help.
 */
std::string program_name;

static void
usage(void)
{
    std::cerr <<
              "Usage: " << program_name << " [-d] [-h]" << std::endl <<
              " -d  enable debugging." << std::endl <<
              " -h  this message" << std::endl << std::endl;
}

static void
process_options(int argc, char *argv[])
{
    int opt;

    opterr = 0;
    while (-1 != (opt = getopt(argc, argv, "hd"))) {
        switch (opt) {
        case 'd':
            debug_enabled = 1;
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        default:
            std::cerr << program_name << ": FATAL: unknown option: -" <<
                      static_cast<char>(optopt) << ". Exiting" << std::endl;
            usage();
            exit(EXIT_FAILURE);
        }
    }
}

int
main(int argc, char *argv[])
{
    program_name = argv[0];
    process_options(argc, argv);

    ndebug(program_name << ' ' << VERSION << ' ' << SQUID_BUILD_INFO <<
           " starting up...");
    std::string buf;
    while (getline(std::cin,buf)) { // will return false at EOF
        ndebug("Got " << buf.length() << " bytes '" << buf << "' from Squid");

        /* send 'OK' result back to Squid */
        SEND_OK("");
    }
    ndebug(program_name << ' ' << VERSION << ' ' << SQUID_BUILD_INFO <<
           " shutting down...");
    return EXIT_SUCCESS;
}

