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
int *p;

int size;
void *addr;
int amt;

int i;
void *my_xmalloc(size_t);
void *my_xcalloc(int, size_t);
int my_xfree(void *);

#define xmalloc my_xmalloc
#define xcalloc my_xcalloc
#define xfree my_xfree
int *size2id_array[2];
int size2id_len=0;
int size2id_alloc=0;

int size2id(size_t);

void init_stats(), print_stats();

typedef struct {
	char *orig_ptr;
	void *my_ptr;
	int id;
	int size;
} memitem;

struct {
	int mallocs,frees,callocs;
} mstat;

memitem *mi;

int 
ptrcmp(const void *a,const void *b) 
{
	return (a==b);
}

main(int argc,char **argv)
{
    char c;
    extern char *optarg; 
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
	switch(mbuf[0]) {
	case 'm': /* malloc */
           sscanf(&mbuf[2],"%d:%s", &size, abuf);
	   mi=malloc(sizeof(memitem)); 
	   mi->orig_ptr=(char *)strdup(abuf);
	   mi->size=size;
	   mi->id=size2id(size);
	   mi->my_ptr=(void *)xmalloc(size);
	   hash_insert(mem_table, mi->orig_ptr, mi);
	   mstat.mallocs++;
	   break;
	case 'c': /* calloc */
	   sscanf(&mbuf[2],"%d:%d:%s",&amt ,&size, abuf);
           mi=malloc(sizeof(memitem));
	   mi->orig_ptr=(char *)strdup(abuf);
	   mi->id=size2id(size);
           mi->size=amt*size;
           mi->my_ptr=(void *)xmalloc(amt*size);
	   hash_insert(mem_table, mi->orig_ptr, mi);
	   mstat.callocs++;
	   break;
	case 'f':
	   sscanf(&mbuf[2],"%s", abuf);
	   mem_entry=hash_lookup(mem_table, abuf);		
	   if (mem_entry==NULL) {
		fprintf(stderr,"invalid free!\n");
	   }
	   mi=(memitem *)mem_entry;
	   xfree(mi->my_ptr);
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
	printf("m/c/f=%d/%d/%d\n",mstat.mallocs,mstat.callocs,mstat.frees);
	printf("types                 : %d\n",size2id_len);
	printf("user time used        : %d.%d\n", (int)myusage.ru_utime.tv_sec,
						(int)myusage.ru_utime.tv_usec);
	printf("system time used      : %d.%d\n", (int)myusage.ru_stime.tv_sec,
                                                (int)myusage.ru_stime.tv_usec);
	printf("max resident set size : %d\n",(int)myusage.ru_maxrss);
	printf("page faults           : %d\n", (int)myusage.ru_majflt);
}

int
size2id(size_t sz)
{
	int j;
	for(j=0;j<size2id_len;j++)
		if (size2id_array[0][j]==sz) {
			size2id_array[1][j]++;
			return j;
		}
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
	size2id_array[1][size2id_len-1]=0;
	return size2id_len-1;
}

