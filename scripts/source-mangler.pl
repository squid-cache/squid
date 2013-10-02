#!/usr/bin/perl -w

# Adds or adjust the source file boilerplate, such as a Copyright statement.
# The boilerplate does not change from one source file to another and is
# assumed to be the first /* comment */ in a source file, before
# the first #include statement.
#
# TODO: Adjust ifndef/define/endif guards for source header files as well.

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

# Debugging section inside a boilerplate comment
my $reDebug = qr{
	^[\s*]*(DEBUG:.*?)$
}mx;

# Copyright-related claims inside a boilerplate comment
my $reClaims = qr{
	(
		(?:AUTHOR\b|				# either author 
		 COPYRIGHT\b(?!\sfile))		# or copyright (except "COPYRIGHT file")
		.*?							# and the claim content itself
	 )$
}xmi;

# The most common GPL text
my $strGpl = 
	"This program is free software; you can redistribute it and/or modify.*?".
	"Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.";
my $reGpl = qr{$strGpl}s;


my $FileName; # for Warn()ings
my %ReportedClaims; # to minimize noise in claims reporting

# process each file in-place; do not touch files on known failures
foreach my $fname (@FileNames) {

	$FileName = $fname;
	my $code = &readFile($fname) or next;
	my $virginCode = $code;

	&Warn("Correct boilerplate already present, skipping:", $code), next if
		$code =~ /\Q$CorrectBoiler\E/s;

	my $boiler;

	if ($code =~ m/$reComment/) {
		my $beforeComment = $`;
		my $comment = $&;

		# Is the matched comment a boilerplate?
		if ($comment !~ m/\n/) {
			# A single line comment is not a boilerplate.
		} elsif ($beforeComment =~ m/\#include/) {
			# A comment after include is not a boilerplate.
		} elsif ($comment =~ m/numerous individuals/) {
			$boiler = $comment;
		} elsif ($comment =~ m@^/\*\*\s@){
			# A Doxygen comment is not a boilerplate.
		} elsif ($comment =~ m/internal declarations|stub file|unit test/i) {
			# These relatively common comments are not boilerplates.
		} else {
			my $tmp = $comment;
			# Remove common text to detect an otherwise empty boilerplate.
			$tmp =~ s/$reDebug//;
			$tmp =~ s/$reGpl//;
			$tmp =~ s/$reClaims//g;
			$tmp =~ s/^[\s*]*(Created on.*?)$//mig;
			if ($tmp =~ m@[^\s*/]@) { # not empty
				&Warn("Unrecognized boilerplate, skipping:", $comment);
				next;
			} else {
				# This is an empty boiler.
				$boiler = $comment;
			}
		}
	}

	if (defined $boiler) {
		my $debugStr = '';
		if ($boiler =~ m/$reDebug/) {
			my $debug = $1;
			$debugStr = "/* $debug */\n\n";
		}

		my @claims = ($boiler =~ m/$reClaims/g);
		if (my @newClaims = grep { !exists $ReportedClaims{$_} } @claims) {
			&Warn("New claim(s) found.");
			foreach my $claim (@newClaims) {
				warn("Claim: $claim\n");
				$ReportedClaims{$claim} = $fname;
			}
		}

		$code =~ s/$reComment//;
		$code = &trimL($code);
		$code = $CorrectBoiler . $debugStr . $code;
	} else {
		# Some files have license declarations way down in the code.
		my $license = 
			"This program is free software|".
			"Permission to use, copy, modify|".
			"Redistribution and use in source and binary forms";
		if ($code =~ m@($license).*?\*/@s) {
			&Warn("Suspected boilerplate in unusual location, skipping.", $`.$&);
			next;
		}
		&Warn("Cannot find old boilerplate, adding new boilerplate.", $code);
		$code = $CorrectBoiler . $code;
	}

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

sub writeFile {
	my ($fname, $code) = @_;
	open(OF, ">$fname") or die("cannot open $fname for writing: $!, stopped");

	print(OF $code) or die("cannot write to $fname: $!, stopped");

	close(OF) or die("cannot finish updating $fname: $!, stopped");
}

# removes all opening whitespace
sub trimL {
	my ($code) = @_;
	$code =~ s/^\n[\n\s]*//m;
	return $code;
}

# removes all trailing whitespace
sub trimR {
	my ($code) = @_;
	$code =~ s/\n[\n\s]*$//m;
	return $code;
}

sub Warn {
	my ($msg, $context) = @_;
	$context = substr($context, 0, 1000) if defined $context;
	$context .= "\n\n" if defined $context;
	$context = '' unless defined $context;
	$msg = sprintf("%s: WARNING: %s\n%s", $FileName, $msg, $context) if defined $FileName;
	warn($msg);
}
