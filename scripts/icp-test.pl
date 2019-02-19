#!/usr/local/bin/perl
#
## Copyright (C) 1996-2019 The Squid Software Foundation and contributors
##
## Squid software is distributed under GPLv2+ license and includes
## contributions from numerous individuals and organizations.
## Please see the COPYING and CONTRIBUTORS files for details.
##

# icp-test.pl 
#
# Duane Wessels, Nov 1996
#
# Usage: icp-test.pl host:port ... < url-list
#
# Sends a continuous stream of ICP queries to a set of caches.  Stdin is
# a list of URLs to request.

require 'getopts.pl';

$|=1;

&Getopts('n');

# just copy this from src/proto.c
@CODES=(
    "ICP_INVALID",
    "ICP_QUERY",
    "UDP_HIT",
    "UDP_MISS",
    "ICP_ERR",
    "ICP_SEND",
    "ICP_SENDA",
    "ICP_DATABEG",
    "ICP_DATA",
    "ICP_DATAEND",
    "ICP_SECHO",
    "ICP_DECHO",
    "ICP_OP_UNUSED0",
    "ICP_OP_UNUSED1",
    "ICP_OP_UNUSED2",
    "ICP_OP_UNUSED3",
    "ICP_OP_UNUSED4",
    "ICP_OP_UNUSED5",
    "ICP_OP_UNUSED6",
    "ICP_OP_UNUSED7",
    "ICP_OP_UNUSED8",
    "UDP_RELOADING",
    "UDP_DENIED",
    "UDP_HIT_OBJ",
    "ICP_END"
);

require 'sys/socket.ph';

$sockaddr = 'S n a4 x8';
($name, $aliases, $proto) = getprotobyname("udp");
$thissock = pack($sockaddr, &AF_INET, 0, "\0\0\0\0");

chop($me=`uname -a|cut -f2 -d' '`);
$myip=(gethostbyname($me))[4];

die "socket: $!\n" unless
	socket (SOCK, &AF_INET, &SOCK_DGRAM, $proto);

$flags = 0;
$flags |= 0x80000000;
$flags |= 0x40000000 if ($opt_n);
$flags = ~0;

while ($ARGV[0] =~ /([^:]+):(\d+)/) {
	$host = $1;
	$port = $2;
	($fqdn, $aliases, $type, $len, $themaddr) = gethostbyname($host);
	$ADDR{$host} = pack('Sna4x8', &AF_INET, $port, $themaddr);
	$ip = join('.', unpack('C4', $themaddr));
	$FQDN{$ip} = $fqdn;
	shift;
}

$rn = 0;
while (<>) {
	print;
	chop;
	$len = length($_) + 1;
	$request_template = sprintf 'CCnNNa4a4x4a%d', $len;
	$request = pack($request_template,
		1,              # C opcode
		2,              # C version
		24 + $len,      # n length
		++$rn,          # N reqnum
		$flags,         # N flags
		'',             # a4 pad
		$myip,          # a4 shostid
		$_);            # a%d payload
	$n = 0;
	foreach $host (keys %ADDR) {
		$port = $PORT{$host};
		@ip = split('\.', $IP{$host});
		$them = pack('SnC4x8', &AF_INET, $port, @ip);
		($sport,@IP) = unpack('x2nC4x8', $ADDR{$host});
		die "send: $!\n" unless send(SOCK, $request, 0, $ADDR{$host});
		$n++;
	}
	while ($n > 0) {
        	$rin = '';
        	vec($rin,fileno(SOCK),1) = 1;
        	($nfound,$timeleft) = select($rout=$rin, undef, undef, 2.0);
		last if ($nfound == 0);
		die "recv: $!\n" unless
                	$theiraddr = recv(SOCK, $reply, 1024, 0);
  		($junk, $junk, $sourceaddr, $junk) = unpack($sockaddr, $theiraddr);
  		$ip = join('.', unpack('C4', $sourceaddr));
        	($type,$ver,$len,$flag,$p1,$p2,$payload) = unpack('CCnx4Nnnx4A', $reply);
        	printf "\t%-20.20s %-10.10s",
			$FQDN{$ip},
			$CODES[$type];
		print " hop=$p1" if ($opt_n);
		print " rtt=$p2" if ($opt_n);
		print "\n";
		$n--;
	}
}

