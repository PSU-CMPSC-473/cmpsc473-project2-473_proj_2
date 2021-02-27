/*
 * mm.c
 *
 * Name: Nahom Regassa, Julien Rovera
 *
 * First Naive implementation based inspired by the implicit list allocator
 * in the text book
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
//#define 

/* rounds up to the nearest multiple of ALIGNMENT */
static size_t align(size_t x)
{
    return ALIGNMENT * ((x+ALIGNMENT-1)/ALIGNMENT);
}
#define SIZE_T_SIZE (align(sizeof(size_t)))
//#define SIZE_PTR(p)  ((size_t*)(((char*)(p)) - SIZE_T_SIZE))
static size_t* SIZE_PTR(void *p){
    return ((size_t*)(((char*)(p)) - SIZE_T_SIZE));
}


/*
 * Initialize: returns false on error, true on success.
 * Doesn't do anything for now
 */
bool mm_init(void)
{
    /* IMPLEMENT THIS */
    return true;
}

/*
 * malloc
 */
void* malloc(size_t size)
{
  // add space in the heap as needed
  int aligned_size = align(size + SIZE_T_SIZE);
  unsigned char *p = mem_sbrk(aligned_size);
  // if failed return null
  if ((long)p == -1)
    return NULL;
  else {
      //update the pointer
    p += SIZE_T_SIZE;
    *SIZE_PTR(p) = size;
    return p;
    return NULL;
  }
}

/*
 * free, doest nothing
 * just for error
 */
void free(void* ptr)
{
    /* IMPLEMENT THIS */
    ptr = ptr;
    return;
}

/*
 * realloc mallocs a new block on the heap
 * and frees up the old block
 */
void* realloc(void* oldptr, size_t size)
{
    void *newptr;
    size_t oldsize;
    
    // if the previous ptr is zero, just malloc new size
    if(oldptr == NULL) {
        return malloc(size);
    }
    // if size is zero just free old pointer
    if(size == 0) {
        free(oldptr);
        return 0;
    }
    // else malloc new
    newptr = malloc(size);

    // don't copy anything new if 
    // malloc fails
    if(newptr == NULL) {
        return 0;
    }
    // if successfull copy the new data
    // get the size of the old pointer
    oldsize = *SIZE_PTR(oldptr);
    if(size < oldsize){ 
        oldsize = size;
    }
    // copy old data and free the old pointer
    memcpy(newptr, oldptr, oldsize);
    free(oldptr);
    return newptr;
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
