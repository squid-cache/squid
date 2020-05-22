#!/usr/bin/perl -w
#
# * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
# *
# * Squid software is distributed under GPLv2+ license and includes
# * contributions from numerous individuals and organizations.
# * Please see the COPYING and CONTRIBUTORS files for details.
#

use strict;
use IO::File;
use Getopt::Long;
use File::Basename;

# This mess is designed to parse the squid config template file
# cf.data.pre and generate a set of HTML pages to use as documentation.
#
# Adrian Chadd <adrian@squid-cache.org>

#
# The template file is reasonably simple to parse. There's a number of
# directives which delineate sections but there's no section delineation.
# A section will "look" somewhat like this, most of the time:
# NAME: <name>
# IFDEF: <the ifdef bit>
# TYPE: <the config type>
# LOC: <location in the Config struct>
# DEFAULT: <the default value(s) - may be multiple lines>
# DEFAULT_IF_NONE: <alternative default value>
# DEFAULT_DOC: <the text to display instead of default value(s)>
# DOC_START
#   documentation goes here
# NOCOMMENT_START
#   stuff which goes verbatim into the config file goes here
# NOCOMMENT_END
# DOC_END
#
# Now, we can't assume its going to be nicely nested, so I'll say that
# sections are delineated by NAME: lines, and then stuff is marked up
# appropriately.
#
# Then we have to fake paragraph markups as well for the documentation.
# We can at least use <PRE> type markups for the NOCOMMENT_START/_END stuff.

#
# Configuration sections are actually broken up by COMMENT_START/COMMENT_END
# bits, which we can use in the top-level index page. Nifty!
#

# XXX NAME: can actually have multiple entries on it; we should generate
# XXX a configuration index entry for each, linking back to the one entry.
# XXX I'll probably just choose the first entry in the list.

# 
# This code is ugly, but meh. We'll keep reading, line by line, and appending
# lines into 'state' variables until the next NAME comes up. We'll then
# shuffle everything off to a function to generate the page.


my ($state) = "";
my (%option);
my (%all_names);
my ($comment);
my (%defines);

my $version = "3.1.0";
my $verbose = '';
my $path = "/tmp";
my $format = "splithtml";
my $pagetemplate;

my ($index) = new IO::File;

my $top = dirname($0);

GetOptions(
	'verbose' => \$verbose, 'v' => \$verbose,
	'out=s' => \$path,
	'version=s' => \$version,
	'format=s' => \$format
	);

if ($format eq "splithtml") {
    $pagetemplate = "template.html";
} elsif ($format eq "singlehtml") {
    $pagetemplate = "template_single.html";
}

# Load defines
my ($df) = new IO::File;

$df->open("$top/../../src/cf_gen_defines", "r") || die;
while(<$df>) {
    $defines{$1} = $2 if /define\["([^"]*)"\]="([^"]*)"/;
}
close $df;
undef $df;

# XXX should implement this!
sub uriescape($)
{
	my ($line) = @_;
	return $line;
}

sub filename($)
{
	my ($name) = @_;
	return $path . "/" . $name . ".html";
}

sub htmlescape($)
{
	my ($line) = @_;
	return "" if !defined $line;
	$line =~ s/&/\&amp;/g;
	$line =~ s/</\&lt;/g;
	$line =~ s/>/\&gt;/g;
	$line =~ s/[^\x{20}-\x{7e}\s]/sprintf ("&#%d;", ord ($1))/ge;
	return $line;
}

sub section_link($)
{
    return uriescape($_[0]).".html" if $format eq "splithtml";
    return "#".$_[0] if $format eq "singlehtml";
}

sub toc_link($)
{
    return "index.html#toc_".uriescape($_[0]) if $format eq "splithtml";
    return "#toc_".uriescape($_[0]) if $format eq "singlehtml";
}

sub alpha_link($)
{
    return "index_all.html#toc_".uriescape($_[0]);
}

#
# Yes, we could just read the template file in once..!
#
sub generate_page($$)
{
	my ($template, $data) = @_;
	my $fh;
	my $fh_open = 0;
	# XXX should make sure the config option is a valid unix filename!
	if ($format eq "splithtml") {
	    my ($fn) = filename($data->{'name'});
	    $fh = new IO::File;
	    $fh->open($fn, "w") || die "Couldn't open $fn: $!\n";
	    $fh_open = 1;
	} else {
	    $fh = $index;
	}

	$data->{"ifdef"} = $defines{$data->{"ifdef"}} if (exists $data->{"ifdef"} && exists $defines{$data->{"ifdef"}});

	my ($th) = new IO::File;
	$th->open($template, "r") || die "Couldn't open $template: $!\n";

	# add in the local variables
	$data->{"title"} = $data->{"name"};
	$data->{"ldoc"} = $data->{"doc"};
	$data->{"toc_link"} = toc_link($data->{"name"});
	$data->{"alpha_link"} = alpha_link($data->{"name"});
	if (exists $data->{"aliases"}) {
		$data->{"aliaslist"} = join(", ", @{$data->{"aliases"}});
	}
	# XXX can't do this and then HTML escape..
	# $data->{"ldoc"} =~ s/\n\n/<\/p>\n<p>\n/;
	# XXX and the end-of-line formatting to turn single \n's into <BR>\n's.

	while (<$th>) {
		# Do variable substitution
		s/%(.*?)%/htmlescape($data->{$1})/ge;
		print $fh $_;
	}
	close $th;
	undef $th;

	if ($fh_open) {
	    close $fh;
	    undef $fh;
	}
}

$index->open(filename("index"), "w") || die "Couldn't open ".filename("index").": $!\n" if ($format eq "splithtml");
$index->open($path, "w") || die "Couldn't open ".filename("index").": $!\n" if ($format eq "singlehtml");
print $index <<EOF
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8" />
    <title>Squid $version configuration file</title>
    <meta name="keywords" content="squid squid.conf config configure" />
    <meta name="description" content="Squid $version" />
    <link rel="stylesheet" type="text/css" href="http://www.squid-cache.org/default.css" />
    <link rel="stylesheet" type="text/css" href="http://www.squid-cache.org/cfgman.css" />
</head>
<body>
EOF
;


my ($name, $data);
my (@chained);

my $in_options = 0;
sub start_option($$)
{
    my ($name, $type) = @_;
    if (!$in_options) {
	print $index "<ul>\n";
	$in_options = 1;
    }
    return if $type eq "obsolete";
    print $index '    <li><a href="' . htmlescape(section_link($name)) . '" name="toc_' . htmlescape($name) . '">' . htmlescape($name) . "</a></li>\n";
}
sub end_options()
{
    return if !$in_options;
    print $index "</ul>\n";
    $in_options = 0;
}
sub section_heading($)
{
	my ($comment) = @_;
	print $index "<pre>\n";
	print $index $comment;
	print $index "</pre>\n";
}
sub update_defaults()
{
	if (defined($data->{"default_doc"})) {
		# default text description masks out the default value display
		if($data->{"default_doc"} ne "") {
			print "REPLACE: default '". $data->{"default"} ."' with '" . $data->{"default_doc"} . "'\n" if $verbose;
			$data->{"default"} = $data->{"default_doc"};
		}
	}
	# when we have no predefined default use the DEFAULT_IF_NONE
	if (defined($data->{"default_if_none"})) {
		print "REPLACE: default '". $data->{"default"} ."' with '" . $data->{"default_if_none"} . "'\n" if $verbose && $data->{"default"} eq "";
		$data->{"default"} = $data->{"default_if_none"} if $data->{"default"} eq "";
	}
}

while (<>) {
	chomp;
	last if (/^EOF$/);
	if ($_ =~ /^NAME: (.*)$/) {
		my (@aliases) = split(/ /, $1);
		$data = {};
		$data->{'version'} = $version;
		foreach (@aliases) {
		    $all_names{$_} = $data;
		}

		$name = shift @aliases;

		$option{$name} = $data;
		$data->{'name'} = $name;
		$data->{'aliases'} = \@aliases;
		$data->{'default'} = "";
		$data->{'default_doc'} = "";
		$data->{'default_if_none'} = "";

		print "DEBUG: new option: $name\n" if $verbose;
		next;
	} elsif ($_ =~ /^COMMENT: (.*)$/) {
		$data->{"comment"} = $1;
	} elsif ($_ =~ /^TYPE: (.*)$/) {
		$data->{"type"} = $1;
		start_option($data->{"name"}, $data->{"type"});
	} elsif ($_ =~ /^DEFAULT: (.*)$/) {
		if ($1 eq "none") {
		    $data->{"default"} = "$1\n";
		} else {
		    $data->{"default"} .= "$name $1\n";
		}
	} elsif ($_ =~ /^DEFAULT_DOC: (.*)$/) {
		$data->{"default_doc"} .= "$1\n";
	} elsif ($_ =~ /^DEFAULT_IF_NONE: (.*)$/) {
		$data->{"default_if_none"} .= "$1\n";
	} elsif ($_ =~ /^LOC:(.*)$/) {
		$data->{"loc"} = $1;
		$data->{"loc"} =~ s/^[\s\t]*//;
	} elsif ($_ =~ /^DOC_START$/) {
		update_defaults;
		$state = "doc";
	} elsif ($_ =~ /^DOC_END$/) {
		$state = "";
		my $othername;
		foreach $othername (@chained) {
		    $option{$othername}{'doc'} = $data->{'doc'};
		}
		undef @chained;
	} elsif ($_ =~ /^DOC_NONE$/) {
		update_defaults;
		push(@chained, $name);
	} elsif ($_ =~ /^NOCOMMENT_START$/) {
		$state = "nocomment";
	} elsif ($_ =~ /^NOCOMMENT_END$/) {
		$state = "";
	} elsif ($_ =~ /^IFDEF: (.*)$/) {
		$data->{"ifdef"} = $1;
	} elsif ($_ =~ /^#/ && $state eq "doc") {
		$data->{"config"} .= $_ . "\n";
	} elsif ($state eq "nocomment") {
		$data->{"config"} .= $_ . "\n";
	} elsif ($state eq "doc") {
		$data->{"doc"} .= $_ . "\n";
	} elsif ($_ =~ /^COMMENT_START$/) {
		end_options;
		$state = "comment";
		$comment = "";
	} elsif ($_ =~ /^COMMENT_END$/) {
		section_heading($comment);
	} elsif ($state eq "comment") {
		$comment .= $_ . "\n";
	} elsif (/^#/) {
		next;
	} elsif ($_ ne "") {
		print "NOTICE: unknown line '$_'\n";
	}
}
end_options;
print $index "<p><a href=\"index_all.html\">Alphabetic index</a></p>\n" if $format eq "splithtml";
print $index "<p><a href=\"#index\">Alphabetic index</a></p>\n" if $format eq "singlehtml";
print $index "<hr />\n" if $format eq "singlehtml";

# and now, build the option pages
my (@names) = keys %option;
foreach $name (@names) {
	next if $option{$name}->{'type'} eq "obsolete";
	generate_page("${top}/${pagetemplate}", $option{$name});
}

# and now, the alphabetic index file!
my $fh;
my $fh_open = 0;

if ($format eq "splithtml") {
    $fh = new IO::File;
    my ($indexname) = filename("index_all");
    $fh->open($indexname, "w") || die "Couldn't open $indexname for writing: $!\n";
    $fh_open = 1;
    print $fh <<EOF
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8" />
    <title>Squid $version configuration file</title>
    <meta name="keywords" content="squid squid.conf config configure" />
    <meta name="description" content="Squid $version" />
    <link rel="stylesheet" type="text/css" href="http://www.squid-cache.org/default.css" />
    <link rel="stylesheet" type="text/css" href="http://www.squid-cache.org/cfgman.css" />
</head>
<body>
    <div id="header">
        <div id="logo">
            <h1><a href="http://www.squid-cache.org/"><span>Squid-</span>Cache.org</a></h1>
            <h2>Optimising Web Delivery</h2>
	</div>
    </div>

  <p>| <a href="index.html">Table of contents</a> |</p>

  <h1>Alphabetic index of all options</h1>
EOF
;
} elsif ($format eq "singlehtml") {
    $fh = $index;
    print $fh "<h2><a name=\"index\">Alphabetic index of all options</a></h2>\n";
}

print $fh "<ul>\n";

foreach $name (sort keys %all_names) {
	my ($data) = $all_names{$name};
	next if $data->{'type'} eq "obsolete";
	print $fh '    <li><a href="' . uriescape($data->{'name'}) . '.html" name="toc_' . htmlescape($name) . '">' . htmlescape($name) . "</a></li>\n";
}

print $fh "</ul>\n";
if ($fh_open) {
print $fh <<EOF
  <p>| <a href="index.html">Table of contents</a> |</p>
  </body>
</html>
EOF
;
$fh->close;
}
undef $fh;

print $index <<EOF
  </body>
</html>
EOF
;
$index->close;
undef $index;
