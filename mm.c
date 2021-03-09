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
void remove_from_free_list(void* block, size_t size, size_t reqested_size, int c_list);
size_t coalesce(void * ptr, size_t size);
size_t coalesce_previous_block(void * ptr, size_t size, void ** address_pointer);
void split_block(void* block, size_t block_size, size_t requested_size, int c_list);
#define NUM_FREE_LISTS 8

typedef struct root
{
	void * first_block;
	size_t max_size;
}root;
root root_list[NUM_FREE_LISTS];
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
	int i;
	mem_sbrk(8);
	for(i = 0; i < NUM_FREE_LISTS; i ++)
	{
		root_list[i].max_size = 0;
		root_list[i].first_block = 0;
	}
	return true;
}

/*
 * malloc
 */
void* malloc(size_t size)
{	
	/*void* longest_list_first_block;
	void* shortest_list_first_block;
	void* shortest_list_first_block2;
	size_t longest_list_fb_size;
	size_t shortest_size1;
	size_t shortest_size2;*/
	/*if(number_of_calls > 50)
	{
		longest_list_first_block = root_list[4].first_block;
		if(longest_list_first_block != 0)
		{
			longest_list_fb_size = (size_t)mem_read(longest_list_first_block, 8);
			split_block(longest_list_first_block, longest_list_fb_size, longest_list_fb_size/2, 4);
			free(longest_list_first_block + 8);
		}	
		number_of_calls = 0;
	}
	if(number_of_calls >= 25)
	{
		shortest_list_first_block = root_list[0].first_block;
		shortest_list_first_block2 = root_list[1].first_block;
		if(shortest_list_first_block != 0)
		{
			shortest_size1 = (size_t)mem_read(shortest_list_first_block, 8);	
			shortest_size1 = coalesce(shortest_list_first_block, shortest_size1);
			coalesce_previous_block(shortest_list_first_block, shortest_size1, shortest_list_first_block);
			number_of_calls = 0;
		}
		if(shortest_list_first_block2 != 0)
		{			
			shortest_size2 = (size_t)mem_read(shortest_list_first_block2,8);
			shortest_size2 = coalesce(shortest_list_first_block2, shortest_size2);
			coalesce_previous_block(shortest_list_first_block2, shortest_size2, shortest_list_first_block2);
			number_of_calls = 0;
		}
	}*/
	void * block;
	block = find_free_block(size);
	/*printf ("\n\n\n");
	mm_checkheap(149);*/	
	return block;
}


void free(void* ptr)
{
	size_t block_size = (size_t)mem_read((char *) ptr - 8, 8);	
	void * block_starting_address = (char *) ptr - 8;
	void ** bsa_ptr = &block_starting_address;
	size_t real_block_size = coalesce(block_starting_address, block_size);	
	real_block_size = coalesce_previous_block(block_starting_address, real_block_size, bsa_ptr);
	void * block_ending_address = (char *) block_starting_address + real_block_size;
	void * old_first_block;
	size_t old_first_block_size;
	size_t new_first_block_size;	
	int i;
	int c_list = NUM_FREE_LISTS-1;
	mem_write(block_starting_address, (uint64_t)real_block_size,8);
	mem_write((char*) block_starting_address + real_block_size - 8, (uint64_t)real_block_size, 8);
	for(i = 0; i < NUM_FREE_LISTS-1; i ++)
	{
		if(real_block_size - 16 < root_list[i].max_size)
		{
			c_list = i;
			break;
		}
	}
	old_first_block = root_list[c_list].first_block;
	if(old_first_block == 0)
	{
		mem_write((char*)block_ending_address - 16, 0, 8);	
		mem_write((char*)block_starting_address + 8, 0, 8);
		root_list[c_list].first_block = block_starting_address;
	}
	else
	{
		root_list[c_list].first_block = block_starting_address;
		mem_write((char*) block_starting_address + 8, (uint64_t)old_first_block, 8);
		old_first_block_size = (size_t)mem_read(old_first_block, 8);
		new_first_block_size = (size_t)mem_read(block_starting_address,8);
		mem_write((char*) old_first_block + old_first_block_size - 16, (uint64_t)root_list[c_list].first_block, 8);	
		mem_write((char*) block_starting_address + new_first_block_size - 16, (uint64_t)0,8);
	}
	/*printf ("\n\n\n");
	mm_checkheap(194);*/	
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
	void * starting_address = (char*)mem_heap_lo()+8;
	void * current_block;
	size_t current_block_size= 0;
	size_t free_size=0;
	size_t allocated_size=0;
	int num_free_blocks= 0;
	int num_blocks= 0;
	int is_free = 1;
	int prev_is_free = 1;
	current_block = starting_address; 
	while(current_block < mem_heap_hi())
	{
		num_blocks ++;	
		current_block_size = mem_read(current_block, 8);
		prev_is_free = is_free;
		is_free = current_block_size & 1;
		if(is_free == 0)
		{
			num_free_blocks ++;
			free_size += current_block_size;
		}
		else
		{
			allocated_size += current_block_size;
		}
		if(prev_is_free == 0 && is_free == 0)
		{
			printf ("two adjacent free blocks didn't coalesce\n");
			printf ("current block size: %zu\n", current_block_size);
			assert(1 == -1);
		}	
		current_block = (char*)current_block + (current_block_size & -2);
	}
	printf ("total blocks: %d\n", num_blocks);
	printf ("free blocks: %d\n", num_free_blocks);
	printf ("free bytes: %zu\n", free_size);
	printf ("allocated bytes: %zu\n", allocated_size);
	printf ("utilization: %5.2f\n",100.0 * (double)allocated_size /(free_size + allocated_size));
    	return true;
}

void * find_free_block(size_t size)
{
	int i;
	void * next_block;
	size_t block_size;
	size_t aligned_size = align(size);
	uint64_t best_difference = (int64_t)-1;
	void * best_block = NULL;
	size_t best_block_size = 0;
	int c_list = NUM_FREE_LISTS-1;
	if(root_list[0].max_size == 0)
	{	
		root_list[0].max_size = 64;
		root_list[1].max_size = 256;
		root_list[2].max_size = 1024;
		root_list[3].max_size = 4096;
		root_list[4].max_size = 16384;
		root_list[5].max_size = 65536;
		root_list[6].max_size = 262144;
		/*root_list[0].max_size = 32;
		root_list[1].max_size = 64;
		root_list[2].max_size = 128;
		root_list[3].max_size = 256;
		root_list[4].max_size = 512;
		root_list[5].max_size = 1024;
		root_list[6].max_size = 2048;
		root_list[7].max_size = 4096;
		root_list[8].max_size = 8192;
		root_list[9].max_size = 16384;
		root_list[10].max_size = 32768;
		root_list[11].max_size = 65536;
		root_list[12].max_size = 131072;
		root_list[13].max_size = 262144;
		root_list[14].max_size = 524288;*/
	}
	for(i = 0; i < NUM_FREE_LISTS-1;i ++)
	{
		if(align(size) <= root_list[i].max_size)
		{
			c_list = i;
			break;
		}
	}
	while(c_list <= NUM_FREE_LISTS-1)
	{
		next_block = root_list[c_list].first_block;
		while(next_block != 0)
		{
			block_size = (size_t)mem_read((char *) next_block, 8);
			/*printf ("free block size: %zu\n", block_size);
			printf ("requested size: %zu\n", size);*/
			
			if(block_size -16 >= aligned_size)
			{
				if(block_size -16 == aligned_size)
				{
					best_block = next_block;
					best_block_size = block_size;
					break;
				}
				if((block_size - 16 - aligned_size) < best_difference)
				{
					best_difference = block_size - aligned_size;
					best_block = next_block;
					best_block_size = block_size;
				}		
			}
			next_block = (void*)mem_read((char*)next_block+8, 8); 
		}
		if(best_block != 0)
		{
			remove_from_free_list(best_block, best_block_size, aligned_size, c_list);
			return (void *)((char*) best_block + 8);

		}
		c_list ++;
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

void remove_from_free_list(void* block, size_t size, size_t requested_size, int c_list)
{
	void * next_block;
	void * previous_block;
	size_t next_block_size;

	if (size - (requested_size + 16) >= 32)
	{
		split_block(block, size, requested_size, c_list);
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
			root_list[c_list].first_block = next_block;
		}
		if(previous_block != 0 && next_block == 0)
		{
			mem_write((char*)previous_block+8, 0, 8);			
		}	
		if(previous_block == 0 && next_block!= 0)
		{	
			root_list[c_list].first_block = next_block;
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
	int i;
	int c_list= NUM_FREE_LISTS-1;
	if(next_block_address > mem_heap_hi())
	{
		return size&-2;
	}
	next_block_size = (size_t)mem_read(next_block_address, 8);
	for(i = 0; i < NUM_FREE_LISTS-1; i ++)
	{
		if(next_block_size-16 < root_list[i].max_size)
		{
			c_list = i;
			break;
		}
	}
	/* block is not allocated */
	if((next_block_size &1) ==0)
	{
		/*printf ("Next block size from coalesce: %zu\n", next_block_size);*/
		next_block_fwrd_ptr = (void*)mem_read((char*)next_block_address + 8, 8);
		next_block_back_ptr =(void*) mem_read((char*)next_block_address + next_block_size - 16, 8);
		/*printf ("crashing here: %p\n", next_block_fwrd_ptr);*/	
		if(next_block_back_ptr == 0)
		{
			root_list[c_list].first_block = next_block_fwrd_ptr;
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
	int i;
	int c_list = NUM_FREE_LISTS-1;
	if((char*)ptr - 8 < (char*)mem_heap_lo() + 8)
	{
		return size;
	}
	previous_block_size = mem_read((char*)ptr-8, 8);
	for( i = 0;i <NUM_FREE_LISTS-1; i ++)
	{
		if(previous_block_size - 16 < root_list[i].max_size)
		{
			c_list = i;
			break;
		}
	}
	if((previous_block_size &1) ==0)
	{
		previous_block_address = (char*)ptr - previous_block_size;
		previous_block_fwrd_ptr = (void*)mem_read((char*)previous_block_address + 8, 8);
		previous_block_back_ptr = (void*)mem_read((char*)ptr - 16, 8);
		*address_pointer = previous_block_address;
		if(previous_block_back_ptr == 0)
		{
			root_list[c_list].first_block = previous_block_fwrd_ptr;
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
void split_block(void * block, size_t block_size, size_t requested_size, int c_list)
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
		root_list[c_list].first_block = fwrd_ptr;
	}
	else
	{
		mem_write((char*)back_ptr+8, (uint64_t)fwrd_ptr, 8);
	}
	if(fwrd_ptr != 0)
	{
		next_in_list_size = (size_t)mem_read(fwrd_ptr,8);
		mem_write((char*)fwrd_ptr + next_in_list_size - 16, (uint64_t)back_ptr, 8);
	}
	free((char*)new_free_block+8);
}

