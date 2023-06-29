#!/usr/bin/perl -w
#
## Copyright (C) 1996-2023 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

use strict;
use warnings;

# Reads (presumed to be previously vetted) CONTRIBUTORS file.
# Reads untrusted CONTIBUTORS-like new input (without the preamble).
# Reports and ignores invalid new contributor entries.
# Reports and ignores valid new entries already covered by CONTRIBUTORS.
# Prints CONTRIBUTORS preamble, vetted entries, and imported new contributors
# using CONTRIBUTORS file format.

my $VettedLinesIn = 0;
my $NewLinesIn = 0;
my $LinesOut = 0;
my $SkippedBanned = 0;
my $SkippedAlreadyVetted = 0;
my $SkippedNewDuplicates = 0;
my $SkippedEmptyLines = 0;
my $SkippedBadLines = 0;

my @VettedContributors = ();
my @NewContributors = ();
my %Problems = ();

exit &main();

# whether the new entry is already sufficiently represented by the vetted one
sub similarToVetted
{
    my ($c, $vetted) = @_;

    # It is not critical (and is probably impossible) to get this right for
    # every single use case. When the script gets it wrong, a human can always
    # update CONTRIBUTORS manually. Rare mistakes are not a big deal.

    # same email is enough, regardless of name differences
    if (defined($c->{email}) && defined($vetted->{email})) {
        my $diff = &caseCmp($c->{email}, $vetted->{email});
        return 1 if $diff == 0;
    }

    # same name is enough, regardless of email differences
    if (defined($c->{name}) && defined($vetted->{name})) {
        my $diff = &caseCmp($c->{name}, $vetted->{name});
        return 1 if $diff == 0;
    }

    return 0;
}

# ensures final, stable order while guaranteeing no duplicates
sub cmpContributorsForPrinting
{
    my ($l, $r) = @_;

    my $diff = &cmpContributors($l, $r);
    return $diff if $diff;

    # now case-sensitively
    $diff = &contributorToString($l) cmp &contributorToString($r);
    return $diff if $diff;
    die("duplicates in output");
}

# case-insensitive comparison
# for list stability, use cmpContributorsForPrinting() when ordering entries
sub cmpContributors
{
    my ($l, $r) = @_;

    # Compare based on the first field (name or, if nameless, email)
    # Do not use &contributorToString() on nameless entries because the
    # leading "<" in such entries will group them all together. We want
    # nameless entries to use email (without brackets) for this comparison.
    my $lRep = defined($l->{name}) ? $l->{name} : $l->{email};
    my $rRep = defined($r->{name}) ? $r->{name} : $r->{email};
    die() unless defined($lRep) && defined($rRep);
    my $diff = &caseCmp($lRep, $rRep);
    return $diff if $diff;

    # nameless entries go after (matching) named entries
    return -1 if defined($l->{name}) && !defined($r->{name});
    return +1 if !defined($l->{name}) && defined($r->{name});
    return 0 if !defined($l->{name}) && !defined($r->{name});

    # we are left with the same-name entries
    die() unless defined($l->{name}) && defined($r->{name});

    # email-less entries go after (same-name) with-email entries
    return -1 if defined($l->{email}) && !defined($r->{email});
    return +1 if !defined($l->{email}) && defined($r->{email});
    return 0 if !defined($l->{email}) && !defined($r->{email});

    # we are left with same-name entries with emails
    return &caseCmp($l->{email}, $r->{email});
}

# whether the given entry is (better) represented by the other one
sub worseThan
{
    my ($l, $r) = @_;

    return 1 if &cmpContributors($l, $r) == 0; # pure duplicate

    return 1 if !defined($l->{name}) && defined($r->{email}) &&
        $l->{email} eq $r->{email};

    return 1 if !defined($l->{email}) && defined($r->{name}) &&
        $l->{name} eq $r->{name};

    return 0;
}

# whether the entry should be excluded based on some out-of-band rules
sub isManuallyExcluded
{
    my ($c) = @_;
    return lc(contributorToString($c)) =~ /squidadm/; # a known bot
}

sub contributorToString
{
    my ($c) = @_;

    if (defined($c->{name}) && defined($c->{email})) {
        return sprintf("%s <%s>", $c->{name}, $c->{email});
    }

    if (defined $c->{name}) {
        return $c->{name};
    }

    die() unless defined $c->{email};
    return sprintf("<%s>", $c->{email});
}

sub printContributors
{
    foreach my $c (sort { &cmpContributorsForPrinting($a, $b) } (@VettedContributors, @NewContributors)) {
        my $entry = &contributorToString($c);
        die() unless defined $entry && length $entry;
        &lineOut("    $entry\n");
    }
}

# convert an unvetted/raw input line into a {name, email, ...} object
sub parseContributor
{
    s/^\s+|\s+$//g; # trim
    my $trimmedRaw = $_;

    s/\s+/ /g; # canonical space characters
    die() unless length $_;

    return "entry with strange characters" if /[^-,_+'" a-zA-Z0-9@<>().]/;

    my $name = undef();
    my $email = undef();

    if (s/\s*<(.*)>$//) {
        $email = $1 if length $1;

        return "multiple emails" if defined($email) && $email =~ /,/;
        return "suspicious email" if defined($email) && !&isEmail($email);
    }

    # convert: name@example.com <>
    # into:    <name@example.com>
    if (!defined($email) && &isEmail($_)) {
        $email = $_;
        $_ = '';
    }

    $name = $_ if length $_;

    if (defined($name)) {
        return "name that looks like email" if $name =~ /@|<|\sat\s|^unknown$/;

        # strip paired surrounding quotes
        if ($name =~ /^'\s*(.*)\s*'$/ || $name =~ /^"\s*(.*)\s*"$/) {
            $name = $1;
        }
    }

    return "nameless, email-less entry" if !defined($name) && !defined($email);

    return {
        name => $name,
        email => $email,
        raw => $trimmedRaw,
    };
}

# Handle CONTRIBUTORS file, printing preamble and loading vetted entries. The
# parsing rules here are a lot more relaxed because we know that this vetted
# content might contain manual entries that violate our automated rules.
sub loadVettedContributors
{
    my ($vettedFilename) = @_;
    open(IF, "<$vettedFilename") or die("Cannot open $vettedFilename: $!\n");
    while (<IF>) {
        my $original = $_;
        ++$VettedLinesIn;

        if (s/^\S// || s/^\s*$//) {
            # preamble and its terminator (a more-or-less empty line)
            &lineOut($original);
            next;
        }

        chomp;

        s/^\s+|\s+$//g; # trim
        my $trimmedRaw = $_;

        my ($name, $email);
        if (s/\s*<(.+)>$//) {
            $email = $1;
        }
        if (length $_) {
            $name = $_;
            die("Malformed vetted entry name: ", $name) if $name =~ /[@<>]/;
        }

        die("Malformed $vettedFilename entry:", $original) if !defined($name) && !defined($email);

        push @VettedContributors, {
            name => $name,
            email => $email,
            raw => $trimmedRaw,
        };
    }
    close(IF) or die();
    die() unless @VettedContributors;
}

# import contributor (name, email) pairs from CONTRIBUTOR-like input
# skip unwanted entries where the decision can be made w/o knowing all entries
sub loadCandidates
{
    while (<>) {
        ++$NewLinesIn;
        my $original = $_;
        chomp;

        s/^\s+|\s+$//g; # trim

        if (!length $_) {
            ++$SkippedEmptyLines;
            next;
        }

        my $c = &parseContributor();
        die() unless $c;

        if (!ref($c)) {
            &noteProblem("Skipping %s: %s", $c, $original);
            ++$SkippedBadLines;
            next;
        }
        die(ref($c)) unless ref($c) eq 'HASH';

        if (&isManuallyExcluded($c)) {
            &noteProblem("Skipping banned entry: %s\n", $c->{raw});
            ++$SkippedBanned;
            next;
        }

        if (my ($vettedC) = grep { &similarToVetted($c, $_) } @VettedContributors) {
            &noteProblem("Skipping already vetted:\n    %s\n    %s\n", $vettedC->{raw}, $c->{raw})
                unless &contributorToString($vettedC) eq &contributorToString($c);
            ++$SkippedAlreadyVetted;
            next;
        }

        push @NewContributors, $c;
    }
}

sub pruneCandidates
{
    my @ngContributors = ();

    while (@NewContributors) {
        my $c = pop @NewContributors;
        if (my ($otherC) = grep { &worseThan($c, $_) } (@VettedContributors, @NewContributors, @ngContributors)) {
            &noteProblem("Skipping very similar:\n    %s\n    %s\n", $otherC->{raw}, $c->{raw})
                unless &contributorToString($otherC) eq &contributorToString($c);
            ++$SkippedNewDuplicates;
            next;
        }
        push @ngContributors, $c;
    }

    @NewContributors = @ngContributors;
}

sub lineOut {
    print(@_);
    ++$LinesOut;
}

# report the given problem, once
sub noteProblem {
    my $format = shift;
    my $problem = sprintf($format, @_);
    return if exists $Problems{$problem};
    $Problems{$problem} = undef();
    print(STDERR $problem);
}

sub isEmail
{
    my ($raw) = @_;
    return $raw =~ /^\S+@\S+[.]\S+$/;
}

sub caseCmp
{
    my ($l, $r) = @_;
    return (uc $l) cmp (uc $r);
}

sub main
{
    &loadVettedContributors("CONTRIBUTORS");
    &loadCandidates();
    &pruneCandidates();

    my $loadedNewContributors = scalar @NewContributors;
    die("$NewLinesIn != $SkippedEmptyLines + $SkippedBadLines + $SkippedBanned + $SkippedAlreadyVetted + $SkippedNewDuplicates + $loadedNewContributors; stopped")
        unless $NewLinesIn == $SkippedEmptyLines + $SkippedBadLines + $SkippedBanned + $SkippedAlreadyVetted + $SkippedNewDuplicates + $loadedNewContributors;

    &printContributors();

    # TODO: Disable this debugging-like dump (by default). Or just remove?
    printf(STDERR "Vetted lines in:     %4d\n", $VettedLinesIn);
    printf(STDERR "Updated lines out:   %4d\n", $LinesOut);
    printf(STDERR "\n");
    printf(STDERR "New lines in:        %4d\n", $NewLinesIn);
    printf(STDERR "Skipped empty lines: %4d\n", $SkippedEmptyLines);
    printf(STDERR "Skipped banned:      %4d\n", $SkippedBanned);
    printf(STDERR "Skipped similar:     %4d\n", $SkippedAlreadyVetted);
    printf(STDERR "Skipped duplicates:  %4d\n", $SkippedNewDuplicates);
    printf(STDERR "Skipped bad lines:   %4d\n", $SkippedBadLines);
    printf(STDERR "\n");
    printf(STDERR "Vetted contributors: %3d\n", scalar @VettedContributors);
    printf(STDERR "New contributors:    %3d\n", scalar @NewContributors);
    printf(STDERR "Contributors out:    %3d\n", @VettedContributors + @NewContributors);

    return 0;
}

