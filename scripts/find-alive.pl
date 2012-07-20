#!/usr/bin/perl -w

# Reads cache.log from STDIN, preferrably with full debugging enabled.
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
	HttpReq => [
		'\bHttpRequest.* constructed, this=(\S+)',
		'\bHttpRequest.* destructed, this=(\S+)',
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
		'cbdataAlloc: (\S+)',
		'cbdataFree: Freeing (\S+)',
	],
	FD => [
		'fd_open.*\sFD (\d+)',
		'fd_close\s+FD (\d+)',
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

my %Alive = ();
my $Count = 0;
while (<STDIN>) {
	if (/$reConstructor/) {
		#die($_) if $Alive{$1};
		$Alive{$1} = $_;
		++$Count;
	} 
	elsif (/$reDestructor/) {
		#warn("unborn: $_") unless $Alive{$1};
		$Alive{$1} = undef();
	}
}

printf(STDERR "Found %d %s\n", $Count, $Thing);

my $AliveCount = 0;
foreach my $alive (sort grep { defined($_) } values %Alive) {
	next unless defined $alive;
	printf("Alive: %s", $alive);
	++$AliveCount;
}

printf(STDERR "found %d still-alive %s\n", $AliveCount, $Thing);

exit(0);
