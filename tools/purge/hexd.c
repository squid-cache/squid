#include <ctype.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

unsigned char
xlate( unsigned char ch )
{
  return (isprint(ch & 0x7f) ? ch : '.');
}

typedef struct {
  int fd, rsize, cursor;
  size_t bufsize;
  unsigned char* buffer;
} InputByByte;

int
in_open( InputByByte* this, const char* fn, size_t size )
{
  if ( (this->fd = open( fn, O_RDONLY )) == -1 ) return -1;
  if ( (this->buffer=(unsigned char*) malloc(size)) == 0 ) {
    close(this->fd);
    return -1;
  }
  this->bufsize = size;
  this->rsize = this->cursor = 0;
  return 0;
}

int
in_get( InputByByte* this )
     /* 
      * purpose: read next character
      * returns: 0..255 as valid character, -1 for error, -2 for EOF
      */
{
  if ( this->cursor >= this->rsize ) {
    do { 
      this->rsize = read( this->fd, this->buffer, this->bufsize );
    } while ( this->rsize == -1 && errno == EINTR );
    if ( this->rsize > 0 ) this->cursor = 0;
    else return ((-2) - this->rsize);
  }

  return this->buffer[this->cursor++];
}

int
in_close( InputByByte* this )
{
  free((void*) this->buffer);
  return close(this->fd);
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

  if ( in_open(&in,argv[1],32768) == -1 ) {
    perror( "open" );
    return 1;
  }

  for ( ch = in_get(&in); ch >= 0; ) {
    printf( "%08X: ", line );
    memset( b2, 0, sizeof(b2) );
    for ( i=0; i < 16 && ch >= 0; i++ ) {
      printf( "%02X%c", ch, ((i==7) ? '-' : ' ' ) );
      b2[i] = xlate(ch);
      ch = in_get(&in);
    }
    line += i;
    for ( ; i<16; i++ ) fputs("   ",stdout);
    printf( " %s\n", b2 );
  }
  
  return in_close(&in);
}


