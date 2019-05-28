#!/bin/bash 
set -x -e

WORKING_DIRECTORY=$(dirname $(realpath $0))

# run this script inside a hysolate/agent-based container to compile squid
# don't forget to make $PREFIX a host volume to get the output
IMAGEROOT=$1
PREFIX=$2
rm -rf $PREFIX
rm -rf $IMAGEROOT/$PREFIX
./bootstrap.sh
mkdir -p $PREFIX/etc/
cp ./mime.conf $PREFIX/etc/mime.conf
mkdir -p $PREFIX/share/errors/templates/

rm -rf $WORKING_DIRECTORY/build/
mkdir -p $WORKING_DIRECTORY/build/
cd $WORKING_DIRECTORY/build/

if [ $# -eq 3 ] && [ "$3" = "disableOpt" ]; then
	echo "Disabling optimizations"
	export CFLAGS="-O2 -march=core2 -mno-sse4.1 -mno-sse4.2 -mno-sse4 -mno-sse4a -mno-avx2 -mno-bmi -mno-bmi2 -mno-movbe"
	export CXXFLAGS="${CFLAGS}"
fi

OPENSSL_VERSION=1.1.0

wget https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz -qO - | tar xz
(
    cd openssl-$OPENSSL_VERSION
    ./Configure linux-x86_64 --openssldir=$PREFIX --prefix=$PREFIX enable-ec_nistp_64_gcc_128 \
    enable-heartbeats enable-md2 enable-rc5 \
    enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers
    make
    make install
)

#SQUID_VERSION=4.4

#SQUID_MAJOR=$(sed 's@\..*$@@' <<< $SQUID_VERSION)

mkdir -p build
#wget http://www.squid-cache.org/Versions/v$SQUID_MAJOR/squid-$SQUID_VERSION.tar.xz -qO - | tar xJ
cd build
ls  $WORKING_DIRECTORY
echo $WORKING_DIRECTORY
$WORKING_DIRECTORY/configure --disable-shared --enable-static --disable-http-violations\
    --disable-wccp --disable-wccpv2 --disable-snmp --disable-htcp --disable-ipv6 --enable-epoll \
    --disable-auto-locale --without-gnugss --disable-follow-x-forwarded-for \
    --disable-auth --enable-disk-io=Blocking --disable-unlinkd \
    --enable-linux-netfilter --without-netfilter-conntrack \
    --with-openssl=$PREFIX --prefix=$PREFIX
make
make install

rm -rf $WORKING_DIRECTORY/build/
mkdir -p $IMAGEROOT$PREFIX
mv $PREFIX/* $IMAGEROOT$PREFIX

cd $WORKING_DIRECTORY
cp -f ./ERR_ACCESS_DENIED_REDIRECT_HTTP $IMAGEROOT$PREFIX/share/errors/templates/ERR_ACCESS_DENIED_REDIRECT_HTTP
cp -f ./ERR_ACCESS_DENIED $IMAGEROOT$PREFIX/share/errors/templates/ERR_ACCESS_DENIED


cp -fr $IMAGEROOT $OUTPUT_DIR/img
