/*
 * mm.c
 *
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 * Also, read malloclab.pdf carefully and in its entirety before beginning.
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
void * find_free_block(size_t size);
void * create_new_block(size_t size);
void remove_from_free_list(void* block, size_t size);
void print_free_list();
void * first_block;
int number_of_calls;
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

	mem_reset_brk();
	first_block = 0;
	return true;
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
}


void free(void* ptr)
{
	number_of_calls ++;
	size_t block_size = (size_t)mem_read((char *) ptr - 16, 8);	
	size_t real_block_size = block_size &-2;
	void * block_starting_address = (char *) ptr - 16;
	void * block_ending_address = (char *) block_starting_address + real_block_size;
	void * old_first_block = first_block;
	size_t old_first_block_size;
	size_t new_first_block_size;	
	mem_write(block_starting_address, (uint64_t)real_block_size,8);
	mem_write((char*) block_starting_address + real_block_size - 8, (uint64_t)real_block_size, 8);
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
 * realloc mallocs a new block on the heap
 * and frees up the old block
 */
void* realloc(void* oldptr, size_t size)
{
	void * new_block;
	size_t old_size;
	size_t smaller_size;
	uint64_t i;
	old_size = mem_read((char*)oldptr-16, 8)-32;
	free(oldptr);
	new_block = malloc(size);
	
	if (old_size < size)
	{
		smaller_size = old_size;
	}
	else
	{
		smaller_size = size;
	}

	for(i = 0; i < smaller_size; i ++)
	{
		mem_write((char*) new_block+i, mem_read((char*)oldptr+i, 1), 1);
	}
	return new_block;
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
}

void * create_new_block(size_t size)
{
	size_t block_size = align(size) + 32;
	void * block_starting_address;
	block_starting_address = mem_sbrk((intptr_t)block_size);
	mem_write(block_starting_address, (uint64_t)block_size | 1, 8);
	mem_write((char*) block_starting_address + (block_size - 8), (uint64_t)block_size | 1, 8);		
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
	void* next_block_2 = first_block;
	int loops = 0;
	while (next_block_2 != 0&&loops <= 100)
	{
		next_block_2 = (void*)mem_read((char*) next_block_2+ 8, 8);		
	}
}
