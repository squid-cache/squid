#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/time.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "hash.h"

static hash_table *mem_table = NULL;
static hash_link *mem_entry;
struct rusage myusage;

FILE *fp;
char *fn;
int initsiz;
int maxsiz;
int minchunk;
HASHCMP ptrcmp;
char mbuf[256];
char abuf[32];
char *p;

int size;
void *addr;
int amt;

int i;
int a;
void *my_xmalloc(size_t);
void *my_xcalloc(int, size_t);
int my_xfree(void *);

#define xmalloc my_xmalloc
#define xcalloc my_xcalloc
#define xfree my_xfree

int *size2id_array[2];
int size2id_len=0;
int size2id_alloc=0;

typedef struct {
	char orig_ptr[32];
	void *my_ptr;
#ifdef WITH_LIB
	MemPool *pool;
#endif
	int id;
	int size;
} memitem;

struct {
	int mallocs,frees,callocs,reallocs;
} mstat;

memitem *mi;
void size2id(size_t, memitem *);
void badformat();
void init_stats(), print_stats();


int 
ptrcmp(const void *a,const void *b) 
{
	return (a==b);
}

main(int argc,char **argv)
{
    char c;
    extern char *optarg; 
    a=0;
    while ((c = getopt(argc, argv, "f:i:M:m:")) != -1) {
      switch (c) {
	case 'f':
	  fn=strdup(optarg);
	  fp=fopen(fn,"r");
	  break;
	case 'i':
	  initsiz=atoi(optarg);
	  break;
	case 'M':
	  maxsiz=atoi(optarg);
	  break;
	case 'm':
	  minchunk=atoi(optarg);
	  break;
	default:
  	  fprintf(stderr,
		"Usage: %s -f file -M maxsiz -i initsiz -m minchunk",argv[0]);
	  exit(1);
      }
	
    }
    if (!fp) {
	fprintf(stderr,
		"%s pummels %s\n%s . o O ( You't supply a valid tracefile.)\n",
			argv[0], getenv("USER"), argv[0]);
	exit(1);
    }
    mem_table = hash_create(ptrcmp, 229, hash4);         /* small hash table */
    init_stats();

    while (fgets(mbuf, 256, fp)!=NULL) {
#if RUNTIME_STATSA
	a++;
	if (a%20000==0) print_stats();
#endif
	p=NULL;
	switch(mbuf[0]) {
	case 'm': /* malloc */
	   p=strtok(&mbuf[2],":");
	   if (!p) badformat();
	   size=atoi(p);
	   p=strtok(NULL,"\n");
	   if (!p) badformat();
	   mi=malloc(sizeof(memitem)); 
	   strcpy(mi->orig_ptr,p);
	   mi->size=size;
	   size2id(size,mi);
	   mi->my_ptr=(void *)xmalloc(size);
	   hash_insert(mem_table, mi->orig_ptr, mi);
	   mstat.mallocs++;
	   break;
	case 'c': /* calloc */
	   p=strtok(&mbuf[2],":");
	   if (!p) badformat();
	   amt=atoi(p);
	   p=strtok(NULL,":");
	   if (!p) badformat();
	   size=atoi(p);
	   p=strtok(NULL,"\n");
	   if (!p) badformat();
           mi=malloc(sizeof(memitem));
	   strcpy(mi->orig_ptr,p);
	   size2id(size,mi);
           mi->size=amt*size;
           mi->my_ptr=(void *)xmalloc(amt*size);
	   hash_insert(mem_table, mi->orig_ptr, mi);
	   mstat.callocs++;
	   break;
	case 'r':
           p=strtok(&mbuf[2],":");
	   if (!p) badformat();
	   strcpy(abuf,p);
           p=strtok(NULL,":");
	   if (!p) badformat();
	   mem_entry=hash_lookup(mem_table, p);
           if (mem_entry==NULL) {
                fprintf(stderr,"invalid realloc (%s)!\n",p);
		break;
           }
	   mi=(memitem *)mem_entry;
	   xfree(mi->my_ptr);
           strcpy(mi->orig_ptr,abuf);
	   p=strtok(NULL,"\n");
	   if (!p) badformat();
	   mi->my_ptr=(char *)xmalloc(atoi(p)); 
	   mstat.reallocs++;
	   break;
	case 'f':
	   p=strtok(&mbuf[2],"\n");
	   mem_entry=hash_lookup(mem_table, p);		
	   if (mem_entry==NULL) {
		fprintf(stderr,"invalid free (%s)!\n",p);
		break;
	   }
	   mi=(memitem *)mem_entry;
	   xfree(mi->my_ptr);
	   hash_unlink(mem_table, mem_entry, 1);
	   mstat.frees++;
	   break;
	default:
		fprintf(stderr,"%s pummels %s.bad.format\n", argv[0],fn);
		exit(1);
	}

    }
    fclose(fp);
    print_stats();
}

void *
my_xmalloc(size_t a)
{
	return NULL;
}

void *
my_xcalloc(int a, size_t b)
{
	return NULL;
}

int
my_xfree(void *p)
{
	return 0;
}
void
init_stats()
{

}

void
print_stats()
{
	getrusage(RUSAGE_SELF, &myusage);
	printf("m/c/f/r=%d/%d/%d/%d\n",mstat.mallocs,mstat.callocs,
					mstat.frees, mstat.reallocs);
	printf("types                 : %d\n",size2id_len);
	printf("user time used        : %d.%d\n", (int)myusage.ru_utime.tv_sec,
						(int)myusage.ru_utime.tv_usec);
	printf("system time used      : %d.%d\n", (int)myusage.ru_stime.tv_sec,
                                                (int)myusage.ru_stime.tv_usec);
	printf("max resident set size : %d\n",(int)myusage.ru_maxrss);
	printf("page faults           : %d\n", (int)myusage.ru_majflt);
}

void
size2id(size_t sz,memitem *mi)
{
	int j;
	for(j=0;j<size2id_len;j++)
		if (size2id_array[0][j]==sz) {
			size2id_array[1][j]++;
			mi->id=j;
			return;
		}

	/* we have a different size, so we need a new pool */

	mi->id=size2id_len;
#ifdef WITH_LIB
	mi->pool = memPoolCreate(size2id_len, sz);
#endif
	size2id_len++;
	if (size2id_len==1) {
		size2id_alloc=100;
		size2id_array[0]=malloc(size2id_alloc*sizeof(int));
                size2id_array[1]=malloc(size2id_alloc*sizeof(int));
	} else {
	if (size2id_len > size2id_alloc )
		size2id_alloc+=100;
                size2id_array[0]=realloc(size2id_array[0],size2id_alloc*sizeof(int));
                size2id_array[1]=realloc(size2id_array[1],size2id_alloc*sizeof(int));
	}
	
	size2id_array[0][size2id_len-1]=sz;
	size2id_array[1][size2id_len-1]++;
}

void
badformat()
{
    fprintf(stderr,"pummel.bad.format\n");
    exit(1);
}

/* unused code, saved for parts */
const char *
make_nam(int id, int size)
{
    const char *buf = malloc(30); /* argh */
    sprintf((char *)buf, "pl:%d/%d", id, size);
    return buf;
}
