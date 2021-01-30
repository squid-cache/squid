#!/usr/bin/perl
#
# * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
# *
# * Squid software is distributed under GPLv2+ license and includes
# * contributions from numerous individuals and organizations.
# * Please see the COPYING and CONTRIBUTORS files for details.
#

#
# John@MCC.ac.uk
# John@Pharmweb.NET

require "getopts.pl";
&Getopts('FML:');

open (ACCESS, "/opt/Squid/logs/useragent.0");

while (<ACCESS>) {
	($host, $timestamp, $agent) = 
	/^(\S+) \[(.+)\] \"(.+)\"\s/;
	if ($agent ne '-') {
		if ($opt_M) {
		 	$agent =~ tr/\// /;
			$agent =~ tr/\(/ /;
		}
		if ($opt_F) {
			next unless $seen{$agent}++;
		} else {
			@inline=split(/ /, $agent);
			next unless $seen{$inline[0]}++;
		}
	}
}

$total=0;
if (!$opt_L) {$opt_L=0}

print "Summary of User-Agent Strings\n(greater than $opt_L percent)\n\n";

foreach $browser (keys(%seen)) {
        $total=$total+$seen{$browser};
}

foreach $browser (sort keys(%seen)) {
	$percent=$seen{$browser}/$total*100;
	if ($percent >= $opt_L) { write; }
}

print "\n\nTotal entries in log = $total\n";

format STDOUT =
@>>>>>>> :@##.####% : @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$seen{$browser}, $percent, $browser
.
