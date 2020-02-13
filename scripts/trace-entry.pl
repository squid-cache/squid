#!/usr/bin/perl -w
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Reads cache.log and displays lines that correspond to a given store entry.
#
# Store entry can be identified by its key or an anchor slot ID in a rock-style
# map.
#
# Currently, the script reads and remembers many irrelevant lines because it
# does not know which one should be tracked in advance.
# 

use strict;
use warnings;
use Carp;

my @InterestingEntries = @ARGV;
#die("usage: $0 [entry number|key value|pointer address] ...\n");

my $LastEntryId = 0;
my %Entries = ();
my %EntriesByPartId = ();

my %CurrentEntries = ();
my $Kid;
my %Entering = ();
my %Inside = ();

my $DEB;

while (<STDIN>) {
	my $line = $_;
	#$DEB = 1 if /16:53:44.632/;

	($Kid) = (/(kid\d+)[|]/);
	$Kid = 'kid0' unless defined $Kid;

	&enterBlock($., $_) if
		(/[|:] entering\b/ && !/Port::noteRead/) ||
        (/Port::noteRead/ && /handling/);

	next unless $Inside{$Kid};

	while ($line =~ s@\b(entry) (\d+) .*?(\S*_map)@ @) {
		&processEntryPartId("$3.$1", $2);
	}

	while ($line =~ s@\b(slice|slot) (\d+)@ @) {
		&processEntryPartId($1, $2);
	}

	#while ($line =~ s@\b(page) (\w+)@ @) {
	#	&processEntryPartId($1, $2);
	#}

	while ($line =~ s@\b(key) '?(\w+)@ @) {
		&processEntryPartId($1, $2);
	}

	while ($line =~ s@\b([A-Z0-9]{32})\b@ @) {
		&processEntryPartId('key', $1);
	}

	while ($line =~ s@\be:\S*?/(0x\w+)@ @ || $line =~ s@\bStoreEntry\s+(0x\w+)@ @) {
		&processEntryPartId('pointer', $1);
	}

	if ($line ne $_ || /[|:] leaving\b/) {
		if (my $entry = $CurrentEntries{$Kid}) {
			&updateEntry($entry, $Entering{$Kid}) if exists $Entering{$Kid};
			delete $Entering{$Kid};
			&updateEntry($entry, &historyLine($., $_));
		}
	}

	&leaveBlock() if
       (/[|:] leaving\b/ && !/Port::noteRead/) ||
        (/Port::noteRead/ && /handled/);
}


# merge same entries
my %cleanEntries = ();
foreach my $id (sort { $a <=> $b } keys %Entries) {
	my $entry = $Entries{$id};

	next unless &mergeAllLinkedEntries($entry);

	$entry->{id} = 1 + scalar keys %cleanEntries;
	$cleanEntries{$entry->{id}} = $entry;
}
%Entries = %cleanEntries;

printf("Saw %d entries\n", scalar keys %Entries);

if (!@InterestingEntries) { # print all entries
	foreach my $id (sort { $a <=> $b } keys %Entries) {
		my $entry = $Entries{$id};
		reportEntry($entry, 1);
	}
} else {
	foreach my $description (@InterestingEntries) {
		my ($part, $id) = ($description =~ /(\w+)\s+(\w+)/);
		my $entry = &getExistingEntry($part, $id);
		reportEntry($entry, 1);
	}
}

exit(0);

sub enterBlock {
	my ($lineNo, $lineText) = @_;

	$Entering{$Kid} = &historyLine($., $_);
	die("double entrance, stopped") if $Inside{$Kid};
	$Inside{$Kid} = 1;
}

sub leaveBlock {
	$CurrentEntries{$Kid} = undef();
	delete $Entering{$Kid};
	$Inside{$Kid} = 0;
}

sub processEntryPartId {
	my ($part, $id) = @_;

	#warn("XXX1: $Kid| part.id: $part.$id\n") if $DEB;

	my $entry;
	my $curEntry = $CurrentEntries{$Kid};
	my $oldEntry = &getExistingEntry($part, $id);
	if ($curEntry && $oldEntry && $curEntry->{id} != $oldEntry->{id}) {
		&linkEntries($curEntry, $oldEntry, "$part.$id");
		$entry = $curEntry;
	} else {
		$entry = $curEntry ? $curEntry : $oldEntry;
	}
	$entry = &getEntry($part, $id) unless defined $entry;
	$CurrentEntries{$Kid} = $entry;

	$entry->{parts}->{$part} = {} unless exists $entry->{parts}->{$part};
	$entry->{parts}->{$part}->{$id} = $_ unless exists $entry->{parts}->{$part}->{$id};
}

sub historyLine {
	my ($lineCount, $line) = @_;
	return sprintf("#%06d %s", $lineCount, $line);
}

sub updateEntry {
	my ($entry, $historyLine) = @_;

	$entry->{history} .= $historyLine;
}

sub linkEntries {
	my ($e1, $e2, $ctx) = @_;

	$e1->{sameAs}->{$e2->{id}} = 1;
	$e2->{sameAs}->{$e1->{id}} = 1;
}

sub mergeAllLinkedEntries {
	my ($entry) = @_;

	#warn(sprintf("merging %d <-- * %s\n", $entry->{id}, $entry->{merged} ? "skipped" : ""));

	return 0 if $entry->{merged};
	$entry->{merged} = 1;

	foreach my $otherId (keys %{$entry->{sameAs}}) {
		my $otherE = $Entries{$otherId};
		die("missing internal entry$otherId, stopped") unless $otherE;
		next if $otherE->{merged};
		&mergeAllLinkedEntries($otherE);
		&mergeOneEntry($entry, $otherE);
		$otherE->{merged} = 1;
	}

	return 1;
}

sub mergeOneEntry {
	my ($entry, $otherE) = @_;

	#warn(sprintf("merging %d <-- %d\n", $entry->{id}, $otherE->{id}));

	foreach my $part (keys %{$otherE->{parts}}) {
        foreach my $id (keys %{$otherE->{parts}->{$part}}) {
            $entry->{parts}->{$part}->{$id} = $otherE->{parts}->{$part}->{$id};
		}
	}

	$entry->{history} .= $otherE->{history};
}

sub getExistingEntry {
	my ($part, $id) = @_;

	return $EntriesByPartId{$part}->{$id} if exists $EntriesByPartId{$part};
	return undef();
}

sub getEntry {
	my ($part, $id) = @_;

	$EntriesByPartId{$part} = {} unless exists $EntriesByPartId{$part};
	my $entry = $EntriesByPartId{$part}->{$id};
	return $entry if $entry;

	$entry = {
		id => ++$LastEntryId,

		parts => {},

		history => '',

		reported => 0,
	};

	$entry->{parts}->{$part} = {};
	$EntriesByPartId{$part}->{$id} = $entry;
	$Entries{$LastEntryId} = $entry;
	return $entry;
}


sub reportEntry {
	my ($entry, $recursive) = @_;

	return if $entry->{reported};
	$entry->{reported} = 1;

	printf("entry%d:\n", $entry->{id});

	foreach my $part (keys %{$entry->{parts}}) {
		printf("\t%s(s):", $part);
		foreach my $id (keys %{$entry->{parts}->{$part}}) {
			printf(" %s", $id);
		}
		print("\n");
	}

	&reportEntryHistory($entry);
}

sub reportEntryParam {
	my ($entry, $name, $value) = @_;

	$value = $entry->{$name} if @_ < 3;
	$value = '?' unless defined $value;
	$value = "\n$value" if $value =~ /\n/m;
	printf("\t%s: %s\n", $name, $value);
}

sub reportEntryHistory {
	my ($entry) = @_;

	my $history = $entry->{history};
	my @lines = split(/\n/, $history);
	&reportEntryParam($entry, 'history', (scalar @lines) . " lines");

	my $lastKid = '';
	foreach my $line (sort @lines) {
		my ($kid) = ($line =~ /(kid\d+)[|]/);
		$kid = 'kid0' unless defined $kid;

		print "\n" if $lastKid ne $kid;
		print "$line\n";
		$lastKid = $kid;
	}
	print "\n" if @lines;
}
