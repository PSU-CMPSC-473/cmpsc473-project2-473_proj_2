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
void remove_from_free_list(void* block, size_t size, size_t reqested_size);
size_t coalesce(void * ptr, size_t size);
size_t coalesce_previous_block(void * ptr, size_t size, void ** address_pointer);
void split_block(void* block, size_t block_size, size_t requested_size);
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
	number_of_calls = 0;
	mem_reset_brk();
	mem_sbrk(8);
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
	size_t block_size = (size_t)mem_read((char *) ptr - 8, 8);	
	void * block_starting_address = (char *) ptr - 8;
	void ** bsa_ptr = &block_starting_address;
	size_t real_block_size = coalesce(block_starting_address, block_size);	
	real_block_size = coalesce_previous_block(block_starting_address, real_block_size, bsa_ptr);
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
	old_size = mem_read((char*)oldptr-8, 8)-16;
	new_block = malloc(size);
	if(size < old_size)
	{
		smaller_size = size;
	}
	else
	{
		smaller_size = old_size;
	}
	for(i = 0; i < smaller_size; i ++)
	{
		mem_write((char*)new_block+i, (uint64_t)mem_read((char*)oldptr + i, 1), 1);
	}
	free(oldptr);
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
	uint64_t best_difference = 214748364;
	void * best_block = NULL;
	size_t best_block_size;
	next_block = first_block;
	while(next_block != 0)
	{
		if(loops > 1000)
		{
			return NULL;
		}
		block_size = (size_t)mem_read((char *) next_block, 8);
		if(block_size -16 >= size)
		{
			if((block_size - size) < best_difference)
			{
				best_difference = block_size - size;
				best_block = next_block;
				best_block_size = block_size;
			}		
		}
		next_block = (void*)mem_read((char*)next_block+8, 8); 
	}
	if(best_block != 0)
	{
		remove_from_free_list(best_block, best_block_size, align(size));
		return (void *)((char*) best_block + 8);

	}
	return create_new_block(size); 
}

void * create_new_block(size_t size)
{
	size_t block_size = align(size) + 16;
	void * block_starting_address;
	/*size_t written_size;*/
	block_starting_address = mem_sbrk((intptr_t)block_size);
	mem_write(block_starting_address, (uint64_t)block_size | 1, 8);
	mem_write((char*) block_starting_address + (block_size - 8), (uint64_t)block_size | 1, 8);		
	/*written_size = (size_t)mem_read(block_starting_address, 8);*/
	return (char*) block_starting_address + 8;	
}

void remove_from_free_list(void* block, size_t size, size_t requested_size)
{
	void * next_block;
	void * previous_block;
	size_t next_block_size;

	if (size - (requested_size + 16) >= 32)
	{
		split_block(block, size, requested_size);
	}
	else
	{
		next_block = (void*)mem_read((char*) block + 8,8); 	
		previous_block = (void*)mem_read((char*)block + (size - 16), 8);
		mem_write(block, (uint64_t)(size | 1), 8);
		mem_write((char*)block + (size)-8, (uint64_t)(size|1), 8);
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
}
size_t coalesce(void * ptr, size_t size)
{
	void * next_block_address = (char*)ptr + (size&-2);
	void * next_block_back_ptr;
	void * next_block_fwrd_ptr;
	size_t next_block_size;
	size_t next_block_fwrd_ptr_size;
	size_t combined_size;
	if(next_block_address > mem_heap_hi())
	{
		return size&-2;
	}
	next_block_size = (size_t)mem_read(next_block_address, 8);
	/* block is not allocated */
	if((next_block_size &1) != 1)
	{
		
		/*printf ("Next block size from coalesce: %zu\n", next_block_size);*/
		next_block_fwrd_ptr = (void*)mem_read((char*)next_block_address + 8, 8);
		next_block_back_ptr =(void*) mem_read((char*)next_block_address + next_block_size - 16, 8);
		/*printf ("crashing here: %p\n", next_block_fwrd_ptr);*/	
		if(next_block_back_ptr == 0)
		{
			first_block = next_block_fwrd_ptr;
		}		
		else
		{
			mem_write((char*)next_block_back_ptr + 8, (uint64_t)next_block_fwrd_ptr, 8);
		}
		if(next_block_fwrd_ptr != 0)
		{				
			next_block_fwrd_ptr_size = (size_t)mem_read(next_block_fwrd_ptr, 8);
			mem_write((char*)next_block_fwrd_ptr + next_block_fwrd_ptr_size -16, (uint64_t)next_block_back_ptr, 8);
		}
		combined_size = (size&-2) + next_block_size;
		return combined_size;
	}
	return size&-2;
}
size_t coalesce_previous_block(void * ptr, size_t size, void ** address_pointer)
{
	size_t previous_block_size;
	size_t previous_block_fwrd_ptr_size;
	size_t combined_size;
	void * previous_block_address;
	void * previous_block_fwrd_ptr;
	void * previous_block_back_ptr;
	if((char*)ptr - 8 < (char*)mem_heap_lo() + 8)
	{
		return size;
	}
	previous_block_size = mem_read((char*)ptr-8, 8);
	if((previous_block_size &1) != 1)
	{
		previous_block_address = (char*)ptr - previous_block_size;
		previous_block_fwrd_ptr = (void*)mem_read((char*)previous_block_address + 8, 8);
		previous_block_back_ptr = (void*)mem_read((char*)ptr - 16, 8);
		*address_pointer = previous_block_address;
		if(previous_block_back_ptr == 0)
		{
			first_block = previous_block_fwrd_ptr;
		}
		else
		{
			mem_write((char*)previous_block_back_ptr + 8, (uint64_t)previous_block_fwrd_ptr, 8);
		}
		if(previous_block_fwrd_ptr != 0)
		{	
			previous_block_fwrd_ptr_size = (size_t)mem_read(previous_block_fwrd_ptr, 8);
			mem_write((char*)previous_block_fwrd_ptr + previous_block_fwrd_ptr_size - 16, (uint64_t)previous_block_back_ptr, 8);
		}
		combined_size = size + previous_block_size;
		mem_write(previous_block_address, (uint64_t)combined_size, 8);
		mem_write((char*)previous_block_address + combined_size - 8, (uint64_t)combined_size, 8);
		return combined_size;
	}
	return size;
}
void split_block(void * block, size_t block_size, size_t requested_size)
{
	/*printf ("split block called: %p\n", block);
	printf ("block_size: %zu\n", block_size);
	printf ("requested size: %zu\n", requested_size);*/
	void * fwrd_ptr = (void *)mem_read((char*)block+8,8);
	void * back_ptr = (void *)mem_read((char*)block + block_size - 16, 8);
	void * new_free_block;
	size_t new_allocated_block_size = requested_size + 16;
	size_t new_free_block_size = block_size - new_allocated_block_size;
 	size_t next_in_list_size;	
	new_free_block = (char*)block + new_allocated_block_size;
	mem_write(block, (uint64_t)new_allocated_block_size|1, 8);
	mem_write((char*)block + new_allocated_block_size - 8, (uint64_t)new_allocated_block_size|1, 8);
	mem_write(new_free_block, (uint64_t)new_free_block_size, 8);
	mem_write((char*)new_free_block + new_free_block_size - 8, (uint64_t)new_free_block_size,8);
	if(back_ptr == 0)
	{
		first_block = new_free_block;
		mem_write((char*)new_free_block + new_free_block_size - 16, 0, 8);
	}
	else
	{
		mem_write((char*)new_free_block + new_free_block_size - 16, (uint64_t)back_ptr, 8);
		mem_write((char*)back_ptr+8, (uint64_t)new_free_block, 8);
	}
	mem_write((char*)new_free_block + 8, (uint64_t)fwrd_ptr, 8);
	if(fwrd_ptr != 0)
	{
		next_in_list_size = (size_t)mem_read(fwrd_ptr,8);
		mem_write((char*)fwrd_ptr + next_in_list_size - 16, (uint64_t)new_free_block, 8);
	}
}
void print_free_list()
{
	void* next_block_2 = first_block;
	int loops = 0;
	while (next_block_2 != 0&&loops <= 100)
	{
		printf ("next_block 2: %p\n", next_block_2);
		next_block_2 = (void*)mem_read((char*) next_block_2+ 8, 8);		
		loops ++;
	}
	if (loops > 100)
	{
		assert(1 == -1);
	}
}
