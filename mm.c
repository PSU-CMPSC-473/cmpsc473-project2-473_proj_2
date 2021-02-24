/*
 * mm.c
 *
 * Name: [Julien Rovera]
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 * Also, read malloclab.pdf carefully and in its entirety before beginning.
 *
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#include "mm.h"
#include "memlib.h"

/*
 * If you want to enable your debugging output and heap checker code,
 * uncomment the following line. Be sure not to have debugging enabled
 * in your final submission.
 */
// #define DEBUG

#ifdef DEBUG
/* When debugging is enabled, the underlying functions get called */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated */
#define dbg_printf(...)
#define dbg_assert(...)
#endif /* DEBUG */

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#define memset mem_memset
#define memcpy mem_memcpy
#endif /* DRIVER */

/* What is the correct alignment? */
#define ALIGNMENT 16
void * find_free_block(size_t size);
void * first_block;
/* rounds up to the nearest multiple of ALIGNMENT */
static size_t align(size_t x)
{
    return ALIGNMENT * ((x+ALIGNMENT-1)/ALIGNMENT);
}

/*
 * Initialize: returns false on error, true on success.
 */
bool mm_init(void)
{
    void * earliest_block;
    /* IMPLEMENT THIS 
    void* heap_lo;*/ 
    printf ("before mem_init\n");
    mem_init();
    earliest_block = mem_heap_lo();
    mem_sbrk(24);
    mem_write(earliest_block, 0,8);
    mem_write((char *) earliest_block + 8,(uint64_t) earliest_block, 8);
    first_block = earliest_block;
    printf ("after mem_init\n");
    printf ("first_block: %p\n", first_block);
    printf ("heap size: %zu\n", mem_heapsize());
    /*printf ("CALLING mm_init\n");
    heap_lo = mem_heap_hi();
    printf ("size of the heap: %zu\n", mem_heapsize());
    printf ("last heap address: %p\n", heap_lo);*/
    return true;
}

/*
 * malloc
 */
void* malloc(size_t size)
{
    printf ("size: %d\n", (int) size);
    void * block;
    size_t block_size;
    block = find_free_block(size);
    block_size = mem_read(block, 8);
    
/* remember, you need to create a new block with size and pointer data in the first 16 bytes in the size = 0 case*/
    if(block_size == 0)
    {
	mem_sbrk((intptr_t)align(size) + 8);
  	mem_write(block, align(size) + 32, 8);
  	first_block =(char*) block + align(size) + 33;	
    }
    printf ("fist block after malloc: %p\n", first_block);
    printf ("size plus extra 32 bits: %d\n", (int)align(size) + 32);
    assert (1 == -1);
    return (void *)((char *) block + 24);
}

/*
 * free
 */
void free(void* ptr)
{
    /* IMPLEMENT THIS */
    printf ("free heap reading: %d\n",(int) mem_read((char *) ptr - 16, 8));
    assert(1 == -1);
    return;
}

/*
 * realloc
 */
void* realloc(void* oldptr, size_t size)
{
    /* IMPLEMENT THIS */
    return NULL;
}

/*
 * calloc
 * This function is not tested by mdriver, and has been implemented for you.
 */
void* calloc(size_t nmemb, size_t size)
{
    void* ptr;
    size *= nmemb;
    ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}

/*
 * Returns whether the pointer is in the heap.
 * May be useful for debugging.
 */
static bool in_heap(const void* p)
{
    return p <= mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Returns whether the pointer is aligned.
 * May be useful for debugging.
 */
static bool aligned(const void* p)
{
    size_t ip = (size_t) p;
    return align(ip) == ip;
}

/*
 * mm_checkheap
 */
bool mm_checkheap(int lineno)
{
#ifdef DEBUG
    /* Write code to check heap invariants here */
    /* IMPLEMENT THIS */
#endif /* DEBUG */
    return true;
}

void * find_free_block(size_t size)
{
    int found_block = 0;
    void * current_address = first_block;
    void * next_address;
    size_t block_size;
    while(found_block == 0)
    {
	block_size = mem_read(current_address, 8);    	
	printf ("first block size: %d\n", (int)block_size); 
 	if(block_size >= size)
	{
		printf ("current_address returned case 1: %p\n", current_address);
		return current_address;		
	}
	next_address = (void *) mem_read((char*)current_address + 8 , 8);	
        if(next_address == current_address)
	{
		printf ("current_address returned case 2: %p\n", current_address);
		return current_address;
	}
    }
    return NULL;
}
