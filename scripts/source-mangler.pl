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
$CorrectBoiler = &trimL(&trimR($CorrectBoiler));

my $FileName; # for Warn()ings

# process each file in-place; do not touch files on known failures
foreach my $fname (@FileNames) {

	$FileName = $fname;
	my $code = &readFile($fname);
	my $virginCode = $code;

	&Warn("Correct boilerplate already present, skipping"), next if
		$code =~ /\Q$CorrectBoiler\E/s;

	# Look for the current boiler, which may be absent.
	my $boiler;

	# The first /* comment */ before a preprocessor instruction is a boiler.
	my $re = qr{
		^\s*         # optional whitespace before the comment
		(/\*.*?\*/)  # the first comment itself
		[^#]*        # optional non-preprocessor code after the comment
		[#]          # followed by a preprocessor instruction
	}xs;

	$re = qr{
		(/\*.*?\*/)  # a comment
	}xs;

	if ($code =~ s/$re/$CorrectBoiler/) {
		# updated!
		# TODO: if $& contains a DEBUG section, add it after the boiler.
	} else {
		# TODO: we should try other patterns before giving up

		&Warn("Cannot find old boilerplate, skipping");
		next; # TODO: We should add a boilerplate instead of skipping
	}

	&writeFile($fname, $code) unless $code eq $virginCode;
	undef $FileName;
}

exit(0);

sub readFile() {
	my ($fname) = @_;

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
	my ($msg) = @_;
	$msg = sprintf("%s: WARNING: %s\n", $FileName, $msg) if defined $FileName;
	warn($msg);
}
