#!/usr/bin/perl -w
#
## Copyright (C) 1996-2015 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Reads cache.log and displays lines that correspond to the master transaction
# that has a given async job. Master transaction is all activities tied to a
# a single received HTTP request (client side, ACL, ICAP, server side, etc.).
#
# See trace-job.pl for tracing a single job instead of all jobs related to
# a master transaction.
#
# Currently, many master transaction activities are not tracked because they
# do not use AsyncJob API. Eventually, most activities should be identifiable.
#
# Currently, the script reads and remembers all master transactions because it
# does not know which one should be tracked in advance. Eventually, we may
# have a more efficient way of tying master transaction to a job.
# 


use strict;
use warnings;

my @InterestingJobs = @ARGV or die("usage: $0 <job id> ...\n");

my %Jobs = ();

my $inside = 0;
my $entering;

while (<STDIN>) {
	$entering = $_ if !$inside && /[|:] entering\b/;
	undef $entering if /[|:] leaving\b/;

	if (!$inside && /\bstatus in\b.*\b(?:async|job|icapx)(\d+)\b/o) {
		$inside = $1;
		&enterJob($inside);
		&updateJob($inside, $entering) if defined $entering;
		undef $entering;
	} 
	elsif (!$inside && /\b(?:async|job|icapx)(\d+)\b/o) {
		updateJob($1, "$_\n"); # isolated line
	}

	next unless $inside;	

	&updateJob($inside, $_);

	if (/AsyncJob constructed.*\[\S+?(\d+)\]/) {
		&linkJobs($inside, $1, $_);
	}
	
	if (/[|:] leaving\b/) {
		$inside = 0;
	}
}

foreach my $id (@InterestingJobs) {
	# Squid uses asyncNNN, jobNNN, icapxNNN for the same job/transaction
	$id =~ s/^(?:async|job|icapx)(\d+)$/$1/;
	reportJob($id, 1);
}

exit(0);



sub enterJob {
	my ($id) = @_;
	my $job = &getJob($id);
}

sub updateJob {
	my ($id, $line) = @_;

	my $job = &getJob($id);
	$job->{history} .= $line;

	if ($line =~ /\bFD (\d+)/) {
		$job->{fds}->{$1} = 1;
	}
}

sub linkJobs {
	my ($parentId, $kidId, $line) = @_;

	my $parent = $Jobs{$parentId} or die("missing linked job $parentId");
	push @{$parent->{kids}}, $kidId;
	
	my $kid = &getJob($kidId);
	die("two parents for $kidId: ". $kid->{parent}. " and $parentId") if $kid->{parent};
	$kid->{parent} = $parentId;

	$kid->{history} .= $line; # birth
}

sub getJob {
	my $id = shift;

	my $job = $Jobs{$id};
	return $job if $job;

	$job = {
		id => $id,
		kids => [],
		fds => {},
		parent => undef(),

		start => undef(),
		history => '',

		reported => 0,
	};

	$Jobs{$id} = $job;
	return $job;
}


sub reportJob {
	my ($id, $recursive) = @_;

	my $job = $Jobs{$id} or die("Did not see job$id\n");

	# several kids may try to report their common parent
	return if $job->{reported};
	$job->{reported} = 1;

	&reportJob($job->{parent}, 0) if $job->{parent};

	&reportJobParam($id, 'parent');
	&reportJobParam($id, 'kids', join(', ', @{$job->{kids}}));
	&reportJobParam($id, 'FDs', join(', ', keys %{$job->{fds}}));
	&reportJobHistory($id);

	return unless $recursive;

	foreach my $kidId (@{$job->{kids}}) {
		&reportJob($kidId, $recursive);
	}
}

sub reportJobParam {
	my ($id, $name, $value) = @_;
	my $job = $Jobs{$id} or die;

	$value = $job->{$name} if @_ < 3;
	$value = '?' unless defined $value;
	$value = "\n$value" if $value =~ /\n/m;
	printf("job%d %s: %s\n", $id, $name, $value);
}

sub reportJobHistory {
	my ($id) = @_;
	my $job = $Jobs{$id} or die;

	my $history = $job->{history};
	my @lines = split(/\n/, $history);
	&reportJobParam($id, 'history', (scalar @lines) . " entries");

	foreach my $line (@lines) {
		print "$line\n";
		print "\n" if $line =~ /[|:] leaving\b/;
	}
}
