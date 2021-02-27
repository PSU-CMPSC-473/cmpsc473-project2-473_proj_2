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
void * create_new_block(size_t size);
void remove_from_free_list(void* block, size_t size);
void print_free_list();
void * first_block;
int number_of_calls;
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
/*	printf ("called mm_init\n");*/
/*	mem_init();*/
	mem_reset_brk();
	first_block = 0;
	return true;
	number_of_calls = 5;
    /* IMPLEMENT THIS 
    void* heap_lo; 
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
    printf ("CALLING mm_init\n");
    heap_lo = mem_heap_hi();
    printf ("size of the heap: %zu\n", mem_heapsize());
    printf ("last heap address: %p\n", heap_lo);
    return true;*/
}

/*
 * malloc
 */
void* malloc(size_t size)
{
	number_of_calls ++;
	void * block;
	block = find_free_block(size);
	return block;
/*
    printf ("size: %d\n", (int) size);
    void * block;
    size_t block_size;
    block = find_free_block(size);
    block_size = mem_read(block, 8);
    
 remember, you need to create a new block with size and pointer data in the first 16 bytes in the size = 0 case
    if(block_size == 0)
    {
	mem_sbrk((intptr_t)align(size) + 8);
  	mem_write(block, align(size) + 32, 8);
  	first_block =(char*) block + align(size) + 33;	
    }
    printf ("fist block after malloc: %p\n", first_block);
    printf ("size plus extra 32 bits: %d\n", (int)align(size) + 32);
    assert (1 == -1);
    return (void *)((char *) block + 24);*/
}

/*
 * free
 */
void free(void* ptr)
{
	number_of_calls ++;
	size_t block_size = (size_t)mem_read((char *) ptr - 16, 8);	
	void * block_starting_address = (char *) ptr - 16;
	void * block_ending_address = (char *) block_starting_address + block_size;
	void * old_first_block = first_block;
	size_t old_first_block_size;
	size_t new_first_block_size;	
	if(old_first_block == 0)
	{
		mem_write((char*)block_ending_address - 16, 0, 8);	
		mem_write((char*)block_starting_address + 8, 0, 8);
		first_block = block_starting_address;
	}
	else
	{
		first_block = block_starting_address;
		mem_write((char*) block_starting_address + 8, (uint64_t)old_first_block, 8);
		old_first_block_size = (size_t)mem_read(old_first_block, 8);
		new_first_block_size = (size_t)mem_read(block_starting_address,8);
		mem_write((char*) old_first_block + old_first_block_size - 16, (uint64_t)first_block, 8);	
		mem_write((char*) block_starting_address + new_first_block_size - 16, (uint64_t)0,8);
	}
	return;
}

/*
 * realloc
 */
void* realloc(void* oldptr, size_t size)
{
	free(oldptr);
	return malloc(size);
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
	int loops = 0;
	void * next_block;
	size_t block_size;
	next_block = first_block;
	while(next_block != 0)
	{
		loops ++;
		if(loops < 0)
		{
			return NULL;
		}
		block_size = (size_t)mem_read((char *) next_block, 8);
		if(block_size -32 >= size)
		{
			
			remove_from_free_list(next_block, block_size);
			return (void *)((char*) next_block + 16);	
		}
		next_block = (void*)mem_read((char*)next_block+8, 8); 
	}

	return create_new_block(size); 
/*
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
    return NULL;*/
}

void * create_new_block(size_t size)
{
	size_t block_size = align(size) + 32;
	void * block_starting_address;
	block_starting_address = mem_sbrk((intptr_t)block_size);
	mem_write(block_starting_address, (uint64_t)block_size, 8);
	mem_write((char*) block_starting_address + (block_size - 8), (uint64_t)block_size, 8);		
	return (char*) block_starting_address + 16;	
}

void remove_from_free_list(void* block, size_t size)
{
	void * next_block;
	void * previous_block;
	size_t next_block_size;
	next_block = (void*)mem_read((char*) block + 8,8); 
	previous_block = (void*)mem_read((char*)block + (size - 16), 8);
	/*first block in the list*/
	if (previous_block == 0 && next_block == 0)
	{
		first_block = next_block;
	}
	if(previous_block != 0 && next_block == 0)
	{
		mem_write((char*)previous_block+8, 0, 8);			
	}	
	if(previous_block == 0 && next_block!= 0)
	{	
		first_block = next_block;
		next_block_size = (size_t)mem_read(next_block,8);
		mem_write((char*)next_block + next_block_size-16, 0, 8);
	}
	if(previous_block != 0 && next_block != 0)
	{
		mem_write((char*) previous_block + 8, (uint64_t)next_block, 8);
		next_block_size = (size_t)mem_read(next_block,8);
		mem_write((char*)next_block + next_block_size-16, (uint64_t)previous_block, 8);
	}
}
void print_free_list()
{
	return;
	void* next_block_2 = first_block;
	int loops = 0;
	while (next_block_2 != 0&&loops <= 100)
	{
		printf ("next_block: %p\n", next_block_2);
		next_block_2 = (void*)mem_read((char*) next_block_2+ 8, 8);		
	}
}
