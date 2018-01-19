#!/usr/bin/perl
#
## Copyright (C) 1996-2018 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##
#
# helper multiplexer. Talks to squid using the multiplexed variant of
# the helper protocol, and maintains a farm of synchronous helpers
# helpers are lazily started, as many as needed.
# see helper-mux.README for further informations
#
# AUTHOR: Francesco Chemolli <kinkie@squid-cache.org>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
# 
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
# 
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.

use Getopt::Std;
use Data::Dumper;
use FileHandle;
use IPC::Open2;

#mux-ed format: "slot_num non_muxed_request"

# options handling
my %opts=();
$Getopt::Std::STANDARD_HELP_VERSION=1;
getopts('h', \%opts) or die ("unrecognized options");
if (defined $opts{h}) {
	HELP_MESSAGE();
	exit 0;
}
my $actual_helper_cmd=join(" ",@ARGV);

# variables initialization
my %helpers=();
my $rvec='';
vec($rvec,0,1)=1; #stdin
my $nfound;
my ($rd,$wr,$cl);

# signal handlers
$SIG{'HUP'}=\&dump_state;
$SIG{'CHLD'}=\&reaper;
# TODO: signal handling for child dying

# main loop
$|=1;
while(1) {
	print STDERR "selecting\n";
	$nfound=select($rd=$rvec,undef,undef,undef);
	#$nfound=select($rd=$rvec,undef,$cl=$rvec,undef);
	print STDERR "nfound: $nfound\n";
	if ($nfound == -1 ) {
		print STDERR "error in select: $!\n";
		if ($!{ERESTART} || $!{EAGAIN} || $!{EINTR}) {
			next;
		}
		exit 1;
	}
	#print STDERR "cl: ", unpack("b*", $cl) ,"\n";
	print STDERR "rd: ", unpack("b*", $rd) ,"\n";
	# stdin is special
	#if (vec($cl,0,1)==1) { #stdin was closed
	#	print STDERR "stdin closed\n";
	#	exit(0);
	#}
	if (vec($rd,0,1)==1) { #got stuff from stdin
		#TODO: handle leftover buffers? I hope that 40kb are enough..
		$nread=sysread(STDIN,$_,40960); # read 40kb
		# clear the signal-bit, stdin is special
		vec($rd,0,1)=0;
		if ($nread==0) {
			print STDERR "nothing read from stdin\n";
			exit 0;
		}
		foreach $req (split("\n",$_)) {
			dispatch_request($_);
		}
	}
	# find out if any filedesc was closed
	if ($cl != 0) {
		#TODO: better handle helper restart
		print STDERR "helper crash?";
		exit 1;
	}
	#TODO: is it possible to test the whole bitfield in one go?
	#      != won't work.
	foreach $h (keys %helpers) {
		my %hlp=%{$helpers{$h}};
		#print STDERR "examining helper slot $h, fileno $hlp{fno}, filemask ", vec($rd,$hlp{fno},1) , "\n";
		if (vec($rd,$hlp{fno},1)==1) {
			#print STDERR "found\n";
			handle_helper_response($h);
		}
		#no need to clear, it will be reset when iterating
	}
}

sub dispatch_request {
	my $line=$_[0];
	my %h;

	#print STDERR "dispatching request $_";
	$line =~ /^(\d+) (.*)$/;
	my $slot=$1;
	my $req=$2;

	if (!exists($helpers{$slot})) {
		$helpers{$slot}=init_subprocess();
	}
	$h=$helpers{$slot};
	$wh=$h->{wh};
	$rh=$h->{rh};
	$h->{lastcmd}=$req;
	print $wh "$req\n";
}

# gets in a slot number having got some response.
# reads the response from the helper and sends it back to squid
# prints the response back
sub handle_helper_response {
	my $h=$_[0];
	my ($nread,$resp);
	$nread=sysread($helpers{$h}->{rh},$resp,40960);
	#print STDERR "got $resp from slot $h\n";
	print $h, " ", $resp;
	delete $helpers{$h}->{lastcmd};
}

# a subprocess is a hash with members:
#  pid => $pid
#  rh => read handle
#  wh => write handle
#  fno => file number of the read handle
#  lastcmd => the command "in flight"
# a ref to such a hash is returned by this call
sub init_subprocess {
	my %rv=();
	my ($rh,$wh,$pid);
	$pid=open2($rh,$wh,$actual_helper_cmd);
	if ($pid == 0) {
		die "Failed to fork helper process";
	}
	select($rh); $|=1;
	select($wh); $|=1;
	select(STDOUT);
	$rv{rh}=$rh;
	$rv{wh}=$wh;
	$rv{pid}=$pid;
	$rv{fno}=fileno($rh);
	print STDERR "fileno is $rv{fno}\n";
	vec($rvec,$rv{fno},1)=1;
	return \%rv;
}

sub HELP_MESSAGE {
	print STDERR <<EOF
$0 options:
	-h this help message
   arguments:
	the actual helper executable and its arguments.
	it's advisable to prefix it with "--" to avoid confusion
EOF
}

sub dump_state {
	$SIG{'HUP'}=\&dump_state;
	print STDERR "Helpers state:\n",Dumper(\%helpers),"\n";
}

# finds and returns the slot number of a helper, -1 if not found
# args: - key in helpers
#       - value to look for
sub find_helper_slot {
	my ($k,$v) = @_;
	foreach (keys %helpers) {
		return $_ if $helpers{$k}==$v;
	}
	return -1;
}

sub reaper {
	my $child=wait;
	print STDERR "child $child died\n";
	$SIG{'CHLD'}=\&reaper;
	$slot = find_helper_slot('pid',$child);
	print STDERR "slot is $slot\n";
	#TODO: find the died child, if it was mid-process through a request
	#      send a "BH" to squid and de-init its data-structs here
	exit 1;
}

