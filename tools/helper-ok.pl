#!/usr/bin/perl

$|=1;
while (<>) {
	sleep 10;
	print "OK\n";
}
print STDERR "stdin closed, exit\n";
