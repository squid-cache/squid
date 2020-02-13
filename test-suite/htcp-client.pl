#!/usr/bin/perl
#
## Copyright (C) 1996-2020 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# htcp-client.pl
# by Duane Wessels
#
# simple tool to send client HTCP queries
#
# only supports TST and CLR so far
#

use strict;
use warnings;
use IO::Socket::INET;

my $op = shift;
my $url = shift;
my $server = shift;
my %opcodes = (
	NOP => 0,
	TST => 1,
	MON => 2,
	SET => 3,
	CLR => 4,
);

print "sending $op $url to $server\n";

my $op_data = op_data($op, $url);


my $data = data($op_data, $opcodes{$op}, 0, 1, 0, rand 1<<31);
my $auth = auth();

my $htcp = packet($data, $auth);

my $sock = IO::Socket::INET->new(PeerAddr => $server,
		PeerPort => 4827,
		Proto => 'udp');

die "$server: $!" unless $sock;

$sock->send($htcp, 0) || die "send $server: $!";
exit 0;

sub packet {
	my $data = shift;
	my $auth = shift;
	my $hdr = header(length($data) + length($auth));
	printf STDERR "hdr is %d bytes\n", length($hdr);
	printf STDERR "data is %d bytes\n", length($data);
	printf STDERR "auth is %d bytes\n", length($auth);
	$hdr . $data . $auth;
}

sub header {
	my $length = 4 + shift;
	my $major = 0;
	my $minor = 0;
	my $buf;
	pack('nCC', $length, $major, $minor);
}

sub data {
	my $op_data = shift;
	my $opcode = shift;
	my $response = shift;
	my $reserved = 0;
	my $f1 = shift;
	my $rr = shift;
	my $trans_id = shift;
	printf STDERR "op_data is %d bytes\n", length($op_data);
	printf STDERR "response is %d\n", $response;
	printf STDERR "F1 is %d\n", $f1;
	printf STDERR "RR is %d\n", $rr;
	my $length = 8 + length($op_data);
	my $x1 = ($opcode & 0xF) | (($response & 0xF) << 4);
	#my $x2 = ($rr & 0x1) | (($f1 & 0x1) << 1) | (($reserved & 0x3F) << 2);
	my $x2 = ($reserved & 0x3F) | (($f1 & 0x1) << 6) | (($rr & 0x1) << 7);
	pack('nCCNa*', $length, $x1, $x2, $trans_id, $op_data);
}

sub auth {
	pack('n', 2);
}

sub countstr {
	my $str = shift;
	pack('na*', length($str), $str);
}

sub specifier {
	my $method = countstr(shift);
	my $uri = countstr(shift);
	my $version = countstr(shift);
	my $req_hdrs = countstr(shift);
	$method . $uri . $version . $req_hdrs;
}

sub clr {
	my $reason = shift;
	my $reserved = 0;
	my $specifier = shift;
	printf STDERR "CLR specifier is %d bytes\n", length($specifier);
	my $x1 = ($reason & 0xF) | (($reserved & 0x7F) << 4);
	pack('na*', $x1, $specifier);
}

sub tst {
	my $specifier = shift;
	printf STDERR "TST specifier is %d bytes\n", length($specifier);
	pack('a*', $specifier);
}

sub op_data {
	my $op = shift;
	my $url = shift;
	if ($op eq 'CLR') {
		return clr(1, specifier('GET', $url, 'HTTP/1.1', "Accept: */*\r\n"));
	} elsif ($op eq 'TST') {
		return tst(specifier('GET', $url, 'HTTP/1.1', "Accept: */*\r\n"));
	} else {
		print STDERR "unsupported HTCP opcode $op\n";
		exit 1;
	}
}
