/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "configuration/File.h"
#include "dns/EtcHosts.h"
#include "fqdncache.h"
#include "ipcache.h"
#include "parser/Tokenizer.h"
#include "SquidConfig.h"

DefineRunnerRegistratorIn(Dns, EtcHosts);

SBuf Dns::EtcHosts::Path;

void
Dns::EtcHosts::parse()
{
    if (Path.isEmpty() || Path.cmp("none") == 0)
        return;

    etcHostsFile = new Configuration::File(Path.c_str());
    etcHostsFile->load();

    auto line = etcHostsFile->nextLine();
    while (!line.isEmpty()) {

        ::Parser::Tokenizer tok(line);

        // field 1: IP address
        static const auto ipChars = CharacterSet("ip",":.") + CharacterSet::HEXDIG;
        SBuf addr;
        if (!tok.prefix(addr, ipChars)) {
            /* invalid address, ignore and try next line. */
            debugs(1, DBG_IMPORTANT, "WARNING: invalid IP address at " << etcHostsFile->lineInfo());
            line = etcHostsFile->nextLine();
            continue;
        }
        debugs(1, 5, "address is '" << addr << "'");

        // field 2: list of hostnames
        SBufList hosts;
        while (!tok.atEnd()) {

            (void)tok.skipAll(CharacterSet::WSP);
            if (tok.skip('#'))
                break; // ignore trailing comment

            static const auto hostChars = CharacterSet("host",".-_") + CharacterSet::ALPHA + CharacterSet::DIGIT;
            SBuf hostname;
            if (!tok.prefix(hostname, hostChars)) {
                if (!tok.atEnd())
                    debugs(1, DBG_IMPORTANT, "WARNING: invalid hostname at " << etcHostsFile->lineInfo());
                break;
            }

            debugs(1, 5, "got hostname '" << hostname << "'");

            // TODO: obey /etc/resolv.conf NDOTS configuration
            /* For IPV6 addresses also check for a colon */
            if (Config.appendDomain && hostname.find('.') != SBuf::npos && hostname.find(':') != SBuf::npos) {
                hostname.append(Config.appendDomain);
            }

            if (ipcacheAddEntryFromHosts(hostname, addr)) {
                /* invalid address, continuing is useless */
                hosts.clear();
                break;
            }
            hosts.emplace_back(hostname);
        }

        if (!hosts.empty())
            fqdncacheAddEntryFromHosts(addr, hosts);

        line = etcHostsFile->nextLine();
    }
}

void
Dns::EtcHosts::clear()
{
    delete etcHostsFile;
    etcHostsFile = nullptr;
}
