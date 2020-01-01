#!/usr/bin/perl -w
#
# * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
# *
# * Squid software is distributed under GPLv2+ license and includes
# * contributions from numerous individuals and organizations.
# * Please see the COPYING and CONTRIBUTORS files for details.
#

#
# This is a simple module which takes in a Squid format logfile line and breaks it up into
# a perl hash.
# 
# I'm not going to pretend this is 100% accurate just yet but its a start.
# I'm hoping that by placing it into the public domain it (and the other stuff
# I sneak in here) will be debugged and improved by others.
# 
# Adrian Chadd <adrian@squid-cache.org>
# 
# $Id: ParseLog.pm,v 1.1 2007/01/24 06:50:35 adrian Exp $
# 

use strict;

package Squid::ParseLog;

sub parse($) {
	my ($line) = @_;
	my (%t);
	chomp $line;

	$line =~ m/^(.*?) (\d+?) (.*?) (.*?)\/(\d+?) (\d+?) (.*?) (.*?) (.*?) (.*?)\/(.*?) (.*)$/;

	$t{"timestamp"} = $1;
	$t{"reqtime"} = $2;
	$t{"clientip"} = $3;
	$t{"code"} = $4;
	$t{"httpcode"} = $5;
	$t{"size"} = $6;
	$t{"method"} = $7;
	$t{"url"} = $8;
	$t{"username"} = $9;
	$t{"fwdcode"} = $10;
	$t{"fwdip"} = $11;
	$t{"mime"} = $12;

	return \%t;
}

1;
