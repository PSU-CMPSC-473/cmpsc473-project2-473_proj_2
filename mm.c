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
void * earliest_block;
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
    /* IMPLEMENT THIS 
    void* heap_lo;*/ 
    printf ("before mem_init\n");
    mem_init();
    earliest_block = mem_heap_lo();
    printf ("after mem_init\n");
    printf ("earliest block: %p\n", earliest_block);
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
    void * return_pointer;  
    return_pointer = NULL;
    /* IMPLEMENT THIS */
    printf ("entering malloc\n");
    printf ("size: %zu\n", size);
    printf ("size of size_t: %zu\n",sizeof(size_t));
    mem_sbrk(16);
    mem_write(earliest_block, size+16, 8);
    printf ("from heap reading: %d\n",(int) mem_read(earliest_block, 8));
    mem_sbrk((intptr_t)align(size));
    printf ("size of the heap: %zu\n", mem_heapsize());
    return_pointer = (char *)earliest_block + 16;
    earliest_block = (char *) earliest_block + 16 + align(size);
    printf ("return_pointer: %p\n", return_pointer);
    return return_pointer;    
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
