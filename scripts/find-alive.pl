#!/usr/bin/perl -w
#
## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Reads cache.log from STDIN, preferably with full debugging enabled.
# Finds creation and destruction messages for a given class.
# At the end, reports log lines that correspond to still-alive objects.
# Also reports the number of objects found (total and still-alive).
#
# Many classes have unique creation/destruction line patterns so we
# have to hard-code those patterns in the %Pairs table below. That
# table usually contains a few outdated entries.

use strict;
use warnings;

my $Thing = $ARGV[0] or die("usage: $0 <Thing-to-look-for>\n");

# When creation and destriction messages are standardizes, we
# will be able to support any class without this hard-coded table.
# We try to do that now (see "guessing ..." below), but it does
# not always work.
my %Pairs = (
    AsyncCall => [
        'AsyncCall.* constructed, this=(\S+)',
        'AsyncCall.* destruct.*, this=(\S+)',
        ],
    HttpHeaderEntry => [
        '\bHttpHeaderEntry.* created HttpHeaderEntry (\S+)',
        '\bHttpHeaderEntry.* destroying entry (\S+)',
        ],
    ClientSocketContext => [
        '\bClientSocketContext constructing, this=(\S+)',
        '\bClientSocketContext destructed, this=(\S+)',
        ],
    ICAP => [
        '(?:ICAP|Icap).* constructed, this=(\S+)',
        '(?:ICAP|Icap).* destruct.*, this=(\S+)',
        ],
    IcapModXact => [
        'Adaptation::Icap::ModXact.* constructed, this=(\S+)',
        'Adaptation::Icap::ModXact.* destruct.*, this=(\S+)',
        ],
    ICAPClientReqmodPrecache => [
        'ICAPClientReqmodPrecache constructed, this=(\S+)',
        'ICAPClientReqmodPrecache destruct.*, this=(\S+)',
        ],
    HttpStateData => [
        'HttpStateData (\S+) created',
        'HttpStateData (\S+) destroyed',
        ],
    cbdata => [
        'cbdataInternalAlloc: Allocating (\S+)',
        'cbdataRealFree: Freeing (\S+)',
        ],
    FD => [
        'fd_open.*\sFD (\d+)',
        'fd_close\s+FD (\d+)',
        ],
    IpcStoreMapEntry => [
        'StoreMap.* opened .*entry (\d+) for \S+ (\S+)',
        'StoreMap.* closed .*entry (\d+) for \S+ (\S+)',
        ],
    sh_page => [
        'PageStack.* pop: (sh_page\S+) at',
        'PageStack.* push: (sh_page\S+) at',
        ],
    );

if (!$Pairs{$Thing}) {
    warn("guessing construction/destruction pattern for $Thing\n");
    $Pairs{$Thing} = [
        "\\b$Thing construct.*, this=(\\S+)",
        "\\b$Thing destruct.*, this=(\\S+)",
        ];
}

die("unsupported Thing, stopped") unless $Pairs{$Thing};

my $reConstructor = $Pairs{$Thing}->[0];
my $reDestructor = $Pairs{$Thing}->[1];

my %AliveCount = ();
my %AliveImage = ();
my $Count = 0;
while (<STDIN>) {
    if (my @conIds = (/$reConstructor/)) {
        my $id = join(':', @conIds);
        #die($_) if $Alive{$id};
        $AliveImage{$id} = $_;
        ++$Count unless $AliveCount{$id}++;
    }
    elsif (my @deIds = (/$reDestructor/)) {
        my $id = join(':', @deIds);
        if ($AliveCount{$id}) {
            $AliveImage{$id} = undef() unless --$AliveCount{$id};
        } else {
            #warn("unborn: $_");
            # do nothing; we are probably looking at a partial log
        }
    }
}

printf(STDERR "Found %d %s\n", $Count, $Thing);

my $aliveCount = 0;
foreach my $alive (sort grep { defined($_) } values %AliveImage) {
    next unless defined $alive;
    printf("Alive: %s", $alive);
    ++$aliveCount;
}

printf(STDERR "found %d still-alive %s\n", $aliveCount, $Thing);

exit(0);
