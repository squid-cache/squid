#!/usr/bin/perl -w
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# Adds or adjusts the source file boilerplate, such as a Copyright statement.
# The boilerplate is meant to remain constant from one source file to another.
#
# The old boilerplate is assumed to be the first /* comment */ in a source 
# file, before the first #include statement other than #include "squid.h".
# Common old boilerplates are removed, with copyright-related claims contained
# in them logged on stdout for recording in CONTRIBUTORS or some such.
# Copyright and (C) (but not AUTHOR-like) lines are left in sources except
# when we have a permission to move them to CONTRIBUTORS.
#
# The new boilerplate comment is placed at the very beginning of the file,
# followed by old copyright lines, "inspired by" lines, and DEBUG section
# comments (if any were found in the old boilerplate).
#
# The script tries hard to detect files with unusual old boilerplates. When
# detected, the script warns about the problem and leaves the file "as is".

use strict;
use warnings;

die("usage: $0 <boilerplate-file> <source-file> ...\n") unless @ARGV >= 2;
my ($BoilerName, @FileNames) = @ARGV;

my $CorrectBoiler = `cat $BoilerName` or
	die("cannot load boilerplate from $BoilerName: $!, stopped");
$CorrectBoiler = &trimL(&trimR($CorrectBoiler)) . "\n\n";

# the first /* comment */
my $reComment = qr{
	/\*.*?\*/
}xs;

# Debugging section inside a boilerplate comment.
my $reDebug = qr{
	^[\s*]*(DEBUG:.*?)$
}mx;

# Same as $reDebug, but does not match empty DEBUG: statements.
my $reDebugFull = qr{
	^[\s*]*(DEBUG:[^\S\n]*\S.*?)\s*$
}mx;

# Copyright-related claims inside a boilerplate comment
my $reClaims = qr{
	(
		(?:
		 AUTHOR\b(?:.|\n)*?\*[/\s]*$|	# all authors until an "empty" line
		 ORIGINAL\s+AUTHOR\b|	# or not the latest author
		 COPYRIGHT\b(?!\sfile)|	# or copyright (except "COPYRIGHT file")
		 Portions\scopyright|	# or partial copyright
		 (?<!Squid.is.Copyrighted.)\(C\)\s|	# or (C) (except "Squid is ...")
		 Based.upon.original.+code.by\s*\n|	# or this common pearl
		 Modified\sby\s|		# or this
		 BASED\sON:\s			# or this
		)		
		.*?							# and the claim content itself
	)$
}xmi;

# removes common claim prefixes to minimize claim noise
my $reClaimPrefix = qr{
	(?:ORIGINAL\s)?AUTHOR:?|
	based\son\s|
	based\supon\s|
	Portions\s
}xi;

# We have persmission to move these frequent claims to CONTRIBUTORS.
my $reClaimsOkToMove = qr{
	Robert.Collins|<robertc\@squid-cache.org>|<rbtcollins\@hotmail.com>|

	Duane.Wessels|

	Francesco.Chemolli|<kinkie\@squid-cache.org>|<kinkie\@kame.usr.dsi.unimi.it>|

	Amos.Jeffries|<amosjeffries\@squid-cache.org>|<squid3\@treenet.co.nz>|
	Treehouse.Networks.Ltd.|
	GPL.version.2,..C.2007-2013|

	Henrik.Nordstrom|<henrik\@henriknordstrom.net>|
	MARA.Systems.AB|

	Guido.Serassio|<serassio\@squid-cache.org>|<guido.serassio\@acmeconsulting.it>|
}xi;

# inspirations are not copyright claims but should be preserved
my $reInspiration = qr/^[\s*]*(inspired by previous work.*?)$/mi;

# The most common GPL text, with some address variations.
my $strGpl = 
	"This program is free software; you can redistribute it and/or modify".
	"([^*]|[*][^/])+". # not a /* comment */ closure
	"Foundation, Inc., [^\\n]+MA\\s+[-\\d]+, USA\\.";
my $reGpl = qr{$strGpl}s;

# Two most common Squid (C) statements.
my $strSqCopyStart1 =
	"SQUID Web Proxy Cache\\s+http://www.squid-cache.org/";
my $strSqCopyStart2 =
	"SQUID Internet Object Cache\\s+http://squid.nlanr.net/Squid/";
my $strSqCopyEnd =
	"([^*]|[*][^/])+".
	"numerous individuals".
	"([^*]|[*][^/])+".
	"file for full details.";
my $reSquidCopy = qr{($strSqCopyStart1|$strSqCopyStart2)$strSqCopyEnd}s;


my $FileName; # for Warn()ings
my %ReportedClaims; # to minimize noise in claims reporting
$| = 1; # report claims ASAP (but on STDOUT)

# process each file in-place; do not touch files on known failures
foreach my $fname (@FileNames) {

	$FileName = $fname;
	my $code = &readFile($fname) or next;
	my $virginCode = $code;

	&WarnQuiet("Correct boilerplate already present, skipping:", $code), next if
			$code =~ /\Q$CorrectBoiler\E/s;

	my $boiler;

	if ($code =~ m/$reComment/) {
		my $beforeComment = $`;
		my $comment = $&;

		# Is the matched comment a boilerplate?
		if ($comment !~ m/\n/) {
			# A single line comment is not a boilerplate.
		} elsif ($beforeComment =~ m/^\s*\#\s*include\s+(?!"squid.h")/m) {
			# A comment after include is not a boilerplate,
			# but we make an exception for #include "squid.h" common in lib/
		} elsif ($comment =~ m@^/\*\*\s@){
			# A Doxygen comment is not a boilerplate.
		} elsif ($comment =~ m/internal declarations|stub file|unit test/i) {
			# These relatively common comments are not boilerplates.
		} elsif (&digestable($comment)) {
			# Something we can safely replace.
			$boiler = $comment;
		} else {
			&Warn("Unrecognized boilerplate, skipping:", $comment);
			next;
		}
	}

	my $extras = ''; # DEBUG section, inspired by ..., etc.

	if (defined $boiler) {
		my $copyClaims = ''; # formatted Copyright claims extraced from sources
		my $preserveClaims = 0; # whether to preserve them or not

		if (my @rawClaims = ($boiler =~ m/$reClaims/g)) {
			my @claims = map { &claimList($_) } @rawClaims;
			my $count = 0;
			foreach my $claim (@claims) {
				$claim =~ s/\n+/ /gs;		# streamline multiline claims
				$claim =~ s@\*/?@ @g;		# clean comment leftovers
				$claim =~ s/$reClaimPrefix/ /g; # remove common prefixes
				# this one is sucked in from the old standard boilerplate
				$claim =~ s/by the Regents of the University of//;
				$claim =~ s/\s\s+/ /gs;		# clean excessive whitespace
				$claim =~ s/^\s+|\s+$//gs;	# remove excessive whitespace
				next unless length $claim;

				# preserve Copyright claims
				if ($claim =~ m/Copyright|\(c\)/i) {
					$copyClaims .= sprintf(" * %s\n", $claim);

					# Ignore certain claims, assuming we have their permission.
					my $c = $claim;
					$c =~ s/^\s*(Copyright)?[:\s]*([(c)]+)?\s*([0-9,-]+)?\s*(by)?\s*//i; # prefix
					$c =~ s/$reClaimsOkToMove/ /g;
					$c =~ s/[,]//g; # markup leftovers

					# But if one claim is preserved, all must be preserved.
					$preserveClaims = 1 if $c =~ /\S/;
warn($c) if $c =~ /\S/;
				}

				next if exists $ReportedClaims{$claim};
				print("$fname: INFO: Found new claim(s):\n") unless $count++;
				print("Claim: $claim\n");
				$ReportedClaims{$claim} = $fname;
			}
		}
		
		if ($preserveClaims) {
			die("Internal error: $copyClaims") unless length($copyClaims);
			my $prefix = " * Portions of this code are copyrighted and released under GPLv2+ by:";
			my $suffix = " * Please add new claims to the CONTRIBUTORS file instead.";
			$extras .= sprintf("/*\n%s\n%s%s\n */\n\n",
				$prefix, $copyClaims, $suffix);
		}

		if ($boiler =~ m/$reInspiration/) {
			$extras .= sprintf("/* %s */\n\n", ucfirst($1));
		}

		if ($boiler =~ m/$reDebugFull/) {
			$extras .= "/* $1 */\n\n";
		}

		$code =~ s/\s*$reComment\s*/\n\n/ or
			die("internal error: failed to remove expected comment, stopped");
		&digestable($&) or
			die("internal error: unsafe comment removal, stopped");

	} else { # no boilerplate found
		#&Warn("Cannot find old boilerplate, adding new boilerplate.", $code);
	}

	# Some files have license declarations way down in the code so we may not
	# find a boilerplate at all or find an "empty" boilerplate preceeding them.
	my $license =
		"Copyright|".
		"This program is free software|".
		"Permission to use|".
		"Redistribution and use";
	if ($code =~ m@/\*.*?($license).*?\*/@is) {
		# If we replaced what we thought is an old boiler, do not use $` for
		# context because it is based on modified $code and will often mislead.
		my $context = defined $boiler ? $& : ($` . $&);
		&Warn("Suspected boilerplate in an unusual location, skipping:",
			$context);
		next;
	}

	$code = $CorrectBoiler . $extras . &trimL($code);
	&writeFile($fname, $code) unless $code eq $virginCode;
	undef $FileName;
}

exit(0);

sub readFile() {
	my ($fname) = @_;

	if (!-f $fname) {
		&Warn("Skipping directory or a special file.");
		return undef();
	}

	my $code = '';
	open(IF, "<$fname") or die("cannot open $fname: $!, stopped");
	while (<IF>) {
		$code .= $_;
	}
	close(IF);

	&Warn("empty file") unless length $code;
	return $code;
}

sub writeFile() {
	my ($fname, $code) = @_;
	open(OF, ">$fname") or die("cannot open $fname for writing: $!, stopped");

	print(OF $code) or die("cannot write to $fname: $!, stopped");

	close(OF) or die("cannot finish updating $fname: $!, stopped");
}

# split multiclaim claims into an array of single claims
sub claimList() {
	my $multiClaim = shift;

	$multiClaim =~ s/$reDebug//g; # may pretend to continue AUTHORs list
	$multiClaim =~ s/$reInspiration//g; # does not affect (C) claims

	# remove \n that is not used to separate two claims
	$multiClaim =~ s/(Based.upon.original.+code.by\s*)\n/$1 /g;

	return split(/\n/, $multiClaim);
	# return grep { /\S/ } split($reClaimSplitter, $multiClaim);
}

# checks whether a comment contains nothing but the stuff we can either
# safely remove, replace, or move (e.g., DEBUG sections and copyright claims)
sub digestable() {
	my $comment = shift;

	# Remove common text to detect an otherwise empty boilerplate.
	$comment =~ s/$reDebug//;
	$comment =~ s/$reClaims//g;
	$comment =~ s/^[\s*]*(Created on.*?)$//mig;
	$comment =~ s/^[\s*]*(Windows support\s*)$//mig;
	$comment =~ s/^[\s*]*(History added by .*)$//mig;
	$comment =~ s/$reGpl//;
	$comment =~ s/$reSquidCopy//;
	$comment =~ s/$reInspiration//g;
	$comment =~ s/\* Stubs for.*?$//m; # e.g., Stubs for calls to stuff defined in...
	$comment =~ s/\$Id(:.*)?\$//g; # CVS tags
	$comment =~ s/-{60,}//g; # decorations such as -----------...---------
	$comment =~ s/\b\w+\.(h|c|cc|cci)\b//; # Next to last step: a file name.
	$comment =~ s@[\s*/]@@sg; # Last step: whitespace and comment characters.
	return !length($comment);
}

# removes all opening whitespace
sub trimL() {
	my ($code) = @_;
	$code =~ s/^\n[\n\s]*//s;
	return $code;
}

# removes all trailing whitespace
sub trimR() {
	my ($code) = @_;
	$code =~ s/\n[\n\s]*$//s;
	return $code;
}

sub Warn() {
	my ($msg, $context) = @_;

	if (defined $context) {
		my $MaxLen = 1000;
		$context =~ s/$reGpl/... [GPL] .../;
		$context =~ s/$reSquidCopy/... [Standard Squid "numerous individuals" text] .../;
		$context = substr($context, 0, $MaxLen);
		$context = &trimR($context);
		$context .= "\n\n";
	} else {
		$context = '';
	}
	$msg = sprintf("%s: WARNING: %s\n%s", $FileName, $msg, $context) if defined $FileName;
	warn($msg);
}

sub WarnQuiet() {
	my ($msg, $context) = @_;

	$msg = sprintf("%s: WARNING: %s\n", $FileName, $msg) if defined $FileName;
	warn($msg);
}
