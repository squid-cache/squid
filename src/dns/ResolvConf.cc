/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/PackableStream.h"
#include "dns/ResolvConf.h"
#include "tools.h"

Dns::ResolvConf &
Dns::ResolvConf::Current()
{
    static ResolvConf instance;
    return instance;
}

void
Dns::ResolvConf::dump(Packable *e)
{
    PackableStream out(*e);

    out << "# DNS configuration from " << _PATH_RESCONF << ":" << std::endl;

    if (options.ndots != 0)
        out << "#    options ndots:" << options.ndots << std::endl;

    if (!search.empty()) {
        out << "#    search";
        for (const auto &tld: search)
            out << " " << tld;
        out << std::endl;
    }

    if (!nameservers.empty()) {
        for (const auto &ns: nameservers)
            out << "#    nameserver " << ns << std::endl;
    }
    out << std::endl;
}

void
Dns::ResolvConf::load()
{
#if !_SQUID_WINDOWS_
    search.clear();
    nameservers.clear();
    options.clear();

    // default specified for search list
    if (auto *t = getMyHostname()) {
        if ((t = strchr(t, '.')))
            search.emplace_back(SBuf(t+1));
    }

    FILE *fp = fopen(_PATH_RESCONF, "r");
    if (!fp) {
        int xerrno = errno;
        debugs(78, DBG_IMPORTANT, "" << _PATH_RESCONF << ": " << xstrerr(xerrno));
        return;
    }

    char buf[8196]; // 8KB should be enough
    while (fgets(buf, sizeof(buf)-1, fp)) {
        auto *t = strtok(buf, w_space);

        if (!t || *t == '#' || *t == ';')
            continue; // skip empty or comment lines

        if (strcmp(t, "nameserver") == 0) {
            if ((t = strtok(nullptr, w_space)))
                nameservers.emplace_back(SBuf(t));

        } else if (strcmp(t, "domain") == 0) {
            search.clear();
            if ((t = strtok(nullptr, w_space)))
                search.emplace_back(SBuf(t));

        } else if (strcmp(t, "search") == 0) {
            search.clear();
            while (t) {
                if ((t = strtok(nullptr, w_space))) {
                    search.emplace_back(SBuf(t));
                }
            }

        } else if (strcmp(t, "options") == 0) {
            while (t) {
                if (!(t = strtok(nullptr, w_space)))
                    continue;

                if (strncmp(t, "ndots:", 6) == 0) {
                    options.ndots = atoi(t + 6);
                    if (options.ndots < 1)
                        options.ndots = 1;
                }

                // TODO: add support for timeout:N, attempts:N, edns0, rotate, no-check-names, single-request, use-vc, and no-reload

            }
        }
    }

    fclose(fp);
#endif
}
