#include "config.h"

#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

class InputByByte
{
public:
    int open(const char* fn, const size_t size);
    int get();
    int close();

private:
    int fd, rsize, cursor;
    size_t bufsize;
    unsigned char* buffer;
};

int
InputByByte::open(const char* fn, const size_t size )
{
    if ( (fd = open( fn, O_RDONLY )) == -1 ) return -1;
    if ( (buffer=(unsigned char*) malloc(size)) == 0 ) {
        ::close(fd);
        return -1;
    }
    bufsize = size;
    rsize = cursor = 0;
    return 0;
}

int
InputByByte::get()
/*
 * purpose: read next character
 * returns: 0..255 as valid character, -1 for error, -2 for EOF
 */
{
    if ( cursor >= rsize ) {
        do {
            rsize = read(fd, buffer, bufsize );
        } while ( rsize == -1 && errno == EINTR );
        if ( rsize > 0 ) cursor = 0;
        else return ((-2) - rsize);
    }

    return buffer[cursor++];
}

int
InputByByte::close()
{
    free((void*) buffer);
    return close(fd);
}

int
main( int argc, char* argv[] )
{
    int ch, i;
    unsigned line = 0;
    InputByByte in;
    char b2[20];

    if ( argc != 2 ) {
        fprintf( stderr, "Usage: %s filename\n", argv[0] );
        return 1;
    }

    if ( in.open(argv[1],32768) == -1 ) {
        perror( "open" );
        return 1;
    }

    for ( ch = in.get(); ch >= 0; ) {
        printf( "%08X: ", line );
        memset( b2, 0, sizeof(b2) );
        for ( i=0; i < 16 && ch >= 0; i++ ) {
            printf( "%02X%c", ch, ((i==7) ? '-' : ' ' ) );
            b2[i] = (isprint(ch & 0x7f) ? ch : '.');
            ch = in.get();
        }
        line += i;
        for ( ; i<16; i++ ) fputs("   ",stdout);
        printf( " %s\n", b2 );
    }

    return in.close();
}
