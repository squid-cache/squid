#!/usr/bin/perl -w
#
# external_acl helper to Squid to verify NT Domain group
# membership using wbinfo
#
# This program is put in the public domain by Jerry Murdock 
# <jmurdock@itraktech.com>. It is distributed in the hope that it will
# be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# Author:
#   Jerry Murdock <jmurdock@itraktech.com>
#
# Version history:
#   2005-12-24 Guido Serassio <guido.serassio@acmeconsulting.it>
#               Fix for wbinfo from Samba 3.0.21
#
#   2004-08-15 Henrik Nordstrom <hno@squid-cache.org>
#		Helper protocol changed to URL escaped in Squid-3.0
#
#   2005-06-28 Arno Streuli <astreuli@gmail.com>
#               Add multi group check
#
#   2002-07-05 Jerry Murdock <jmurdock@itraktech.com>
#		Initial release


# Disable output buffering
$|=1;           

sub debug {
	# Uncomment this to enable debugging
	#print STDERR "@_\n";
}

#
# Check if a user belongs to a group
#
sub check {
        local($user, $group) = @_;
        $groupSID = `wbinfo -n "$group" | cut -d" " -f1`;
        chop  $groupSID;
        $groupGID = `wbinfo -Y $groupSID`;
        chop $groupGID;
        &debug( "User:  -$user-\nGroup: -$group-\nSID:   -$groupSID-\nGID:   -$groupGID-");
        return 'OK' if(`wbinfo -r \Q$user\E` =~ /^$groupGID$/m);
        return 'ERR';
}

#
# Main loop
#
while (<STDIN>) {
        chop;
	&debug ("Got $_ from squid");
        ($user, @groups) = split(/\s+/);
	$user =~ s/%([0-9a-fA-F][0-9a-fA-F])/pack("c",hex($1))/eg;
 	# test for each group squid send in it's request
 	foreach $group (@groups) {
		$group =~ s/%([0-9a-fA-F][0-9a-fA-F])/pack("c",hex($1))/eg;
 		$ans = &check($user, $group);
 		last if $ans eq "OK";
 	}
	&debug ("Sending $ans to squid");
	print "$ans\n";
}

