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
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

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
/* function declarations */
void * find_free_block(size_t size);
void * create_new_block(size_t size);
void remove_from_free_list(void* block, size_t size, size_t reqested_size, int c_list);
size_t coalesce(void * ptr, size_t size);
size_t coalesce_previous_block(void * ptr, size_t size, void ** address_pointer);
void split_block(void* block, size_t block_size, size_t requested_size, int c_list);
void * find_slab(size_t size);
void * create_slab(size_t size);
bool  free_slab(void* ptr);
size_t find_list(void* ptr);
bool add_slab_cache(void* ptr);
bool search_slab_cache(void* ptr, uint64_t* return_array);
bool remove_slab(void* ptr, void* slab, void* prev_slab, int i, size_t block_size, uint64_t cache_index);
void remove_from_cache(uint64_t cache_index);
void print_cache();
/* number of segregated free lists and the number of slab lists*/
#define NUM_FREE_LISTS 6
#define NUM_SLAB_LISTS 2
/* root structure: points to the first element of a free list and also tracks that lists maximum block size*/
typedef struct root
{
	void * first_block;
	size_t max_size;
}root;
/* slab root structure: points to first element in a slab free list as well as to the last slab that was freed but is still in the list*/
typedef struct slab_root
{
	void* first_slab;
	void* last_freed;
}slab_root;
/* global arrays containing all free roots and slab roots*/
slab_root slab_lists[NUM_SLAB_LISTS];
root root_list[NUM_FREE_LISTS];
int number_of_ops;
float average_malloc_time;
clock_t average_free_time;
clock_t total_m_time;
clock_t total_f_time;
int mallocs;
int frees;
int cache_adds;
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
 * creates a heap offset of 168 to be used for the slab cache
 * initializes the free lists and slab free lists
 */
bool mm_init(void)
{
	int i;
	mem_sbrk(168);
	mem_memset(mem_heap_lo(), 0, 168);
	number_of_ops = 0;
	for(i = 0; i < NUM_SLAB_LISTS; i ++)
	{
		slab_lists[i].first_slab = 0;
		slab_lists[i].last_freed = 0;
	}
	for(i = 0; i < NUM_FREE_LISTS; i ++)
	{
		root_list[i].max_size = 0;
		root_list[i].first_block = 0;
	}
	total_m_time = 0;
	return true;
}

/*
 * malloc: calls find free block and returns its return value
 */
void* malloc(size_t size)
{	
	number_of_ops ++;
	mallocs ++;
	void * block;
	block = find_free_block(size);
	return block;
}

/*
 * free: frees an allocated block or part of a slab.
 * when freeing an entire block, checks the physically next block and previous block
 * and coalesces if possible. updates the explicit free lists by making the newly freed 
 * block the first element of the list
 */
void free(void* ptr)
{
	number_of_ops ++;	
	/* if slabs have been allocated, we loop through the slab lists to see if the thing
 	* we are freeing is part of a slab*/ 
	if(slab_lists[0].first_slab != 0 || slab_lists[1].first_slab != 0)
	{
		if(free_slab(ptr))
		{
			return;
		}
	}
	/* gets the size form the block header as well as calculates the block starting address */
	size_t block_size = (size_t)mem_read((char *) ptr - 8, 8);	
	void * block_starting_address = (char*)ptr - 8;
	/* this pooints to the block starting_address and will be used to update it when we call previous coalesce*/
	void ** bsa_ptr = &block_starting_address;
	/* first coalesces with the block which is physically in front of the one we are freeing */
	size_t real_block_size = coalesce(block_starting_address, block_size);	
	/* then coalesces with the block whcih is physically behind the one we are freeing */
	real_block_size = coalesce_previous_block(block_starting_address, real_block_size, bsa_ptr);
	/* calcule the last address of the block for easy access to back pointer */
	void * block_ending_address = (char *) block_starting_address + real_block_size;
	/* variables to store data corresponding to the old first block in the free list we are going to add this block to */
	void * old_first_block;
	size_t old_first_block_size;
	size_t new_first_block_size;	
	int i;
	int c_list = NUM_FREE_LISTS-1;
	/* updates the new block formed after coalescing with its new size, or simply changes the size to be 
 	* size & -2 to switch the final bit from a one to a zero */
	mem_write(block_starting_address, (uint64_t)real_block_size,8);
	mem_write((char*) block_starting_address + real_block_size - 8, (uint64_t)real_block_size, 8);
	/* computes which free list the block should be located in*/
	for(i = 0; i < NUM_FREE_LISTS-1; i ++)
	{
		if(real_block_size - 16 < root_list[i].max_size)
		{
			c_list = i;
			break;
		}
	}
	/* updates the free list: checks if the list was empty */
	old_first_block = root_list[c_list].first_block;
	/* if the list is empty, this new block is now the first, its front and back pointers will 
 	* be set to zero */ 
	if(old_first_block == 0)
	{
		mem_write((char*)block_ending_address - 16, 0, 8);	
		mem_write((char*)block_starting_address + 8, 0, 8);
		root_list[c_list].first_block = block_starting_address;
	}
	/* otherwise, make the free list's root point to this new block, and update the pointers of the previous first block */
	else
	{
		root_list[c_list].first_block = block_starting_address;
		mem_write((char*) block_starting_address + 8, (uint64_t)old_first_block, 8);
		old_first_block_size = (size_t)mem_read(old_first_block, 8);
		new_first_block_size = (size_t)mem_read(block_starting_address,8);
		/* updateing back pointer of old first block */
		mem_write((char*) old_first_block + old_first_block_size - 16, (uint64_t)root_list[c_list].first_block, 8);	
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
	/* a pointer to the newly allocated block, a variable to track the block's original size
 	* a variable to track the smaller size between the new and old blocks, a variable to be used in loops */
	void * new_block;
	size_t old_size = 0;
	size_t smaller_size;
	uint64_t i;
	
	/* first checks if the block si from a slab and if so computes the blocks size by calling find list */
	if(slab_lists[0].first_slab != 0 || slab_lists[1].first_slab != 0)
	{
		old_size = find_list(oldptr);	
	}
	/* otherwise reads the size field in the block */
	if(old_size == 0)
	{
		old_size = (mem_read((char*)oldptr-8, 8)-16)&-2;
	}
	/* mallocs a new block to be returned */
	new_block = malloc(size);
	/* computes which of the two sizes, the original or the newly requested, is larger */
	if(size < old_size)
	{
		smaller_size = size;
	}
	else
	{
		smaller_size = old_size;
	}
	/* copies all the data from the original block, up to the smaller size */
	for(i = 0; i < smaller_size; i ++)
	{
		mem_write((char*)new_block+i, (uint64_t)mem_read((char*)oldptr + i, 1), 1);
	}
	/* frees the original block */
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
	void * starting_address = (char*)mem_heap_lo()+88;
	int i;
	void * free_block;
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
			for(i = 0; i < NUM_FREE_LISTS; i ++)
			{
				free_block = root_list[i].first_block;
				while(free_block != 0)
				{
					if(free_block == current_block)
					{
						i = 100;
						break;
					}
					free_block = (void*)mem_read((char*)free_block + 8, 8);
				}
				if(i == 100){
					break;
				}
			}
			if(i != 100)
			{
				assert(1 == -1);
			}
		}
		else
		{
			allocated_size += current_block_size;
		}
		if(prev_is_free == 0 && is_free == 0)
		{
			assert(1 == -1);
		}	
		current_block = (char*)current_block + (current_block_size & -2);
	}
	/*printf ("total blocks: %d\n", num_blocks);
	printf ("free blocks: %d\n", num_free_blocks);
	printf ("free bytes: %zu\n", free_size);
	printf ("allocated bytes: %zu\n", allocated_size);
	printf ("utilization: %5.2f\n",100.0 * (double)allocated_size /(free_size + allocated_size));*/
    	return true;
}
/* called by malloc, finds a free block either from the slab lists, or from the free lists, and returns it
 * if no block can be found, a new one is created */
void * find_free_block(size_t size)
{
	/* looping variable */
	int i;
	/* the next block to be examined in the free list */
	void * next_block;
	/* the block-to-be-freed's size and the requested size onece it has been aligned */
	size_t block_size;
	size_t aligned_size = align(size);
	/* tracks the smallest difference between a block's size and the aligned size */
	uint64_t best_difference = (int64_t)-1;
	/* tracks the block with the closest size in a certain free list to the reqested size, as well as said block's size */
	void * best_block = NULL;
	size_t best_block_size = 0;
	/* tracks which free list we are examining, always starts as the unbounded list */
	int c_list = NUM_FREE_LISTS-1;
	/* initializes the free lists */
	if(root_list[0].max_size == 0)
	{	
		root_list[0].max_size = 128;
		root_list[1].max_size = 256;
		root_list[2].max_size = 512;
		root_list[3].max_size = 1024;
		root_list[4].max_size = 2048;
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
       	
	/* calls find slab if the requested size is less than or equal to 32 */
	/*if(aligned_size <= 32)
	{
		return find_slab(aligned_size);
	}*/
	/* computes which free list we should search based on the requested size */
	for(i = 0; i < NUM_FREE_LISTS-1;i ++)
	{
		if(aligned_size <= root_list[i].max_size)
		{
			c_list = i;
			break;
		}
	}
	/* while we haven't looped through all the free lists */
	while(c_list <= NUM_FREE_LISTS-1)
	{
		next_block = root_list[c_list].first_block;
		/* while there are still blocks to be examined in the free list*/
		while(next_block != 0)
		{
			/* read the blocks size */
			block_size = (size_t)mem_read((char *) next_block, 8);
			if(block_size -16 >= aligned_size)
			{
				/* if a perfect match is found, return the block immediately */
				if(block_size -16 == aligned_size)
				{
					best_block = next_block;
					best_block_size = block_size;
					break;
				}
				/* if the size difference is better than the previously observed best difference
 				* update the best difference and its related fields */
				if((block_size - 16 - aligned_size) < best_difference)
				{
					best_difference = block_size - aligned_size;
					best_block = next_block;
					best_block_size = block_size;
				}		
			}
			/* use the front pointer to examine the next block in the list */
			next_block = (void*)mem_read((char*)next_block+8, 8); 
		}
		/* if a block was found, we return it*/
		if(best_block != 0)
		{
			remove_from_free_list(best_block, best_block_size, aligned_size, c_list);
			return (void *)((char*) best_block + 8);
		}
		/* search the next list if no block was found */
		c_list ++;
	}
	/* create a new block if no suitable one was found */
	return create_new_block(size); 
}
/*
 * calls sbrk to create get space for a new block, writes size data and then returns it
 */
void * create_new_block(size_t size)
{
	/* uses sbrk to create the new block */
	size_t block_size = align(size) + 16;
	void * block_starting_address;
	block_starting_address = mem_sbrk((intptr_t)block_size);
	/* writes the size + 16 (to account for the header and footer) or'd with 1 to show that the
 	* block is allocated */ 
	mem_write(block_starting_address, (uint64_t)block_size | 1, 8);
	mem_write((char*) block_starting_address + (block_size - 8), (uint64_t)block_size | 1, 8);		
	/* returns the address + 8 so that the user can write to the block without overwriting the header */
	return (char*) block_starting_address + 8;	
}

/*
 * removes a block from a specified free list, splits the block if possible
 */
void remove_from_free_list(void* block, size_t size, size_t requested_size, int c_list)
{
	/* the logically next block in the free list */
	void * next_block;
	/* the logically previous block in the free list */
	void * previous_block;
	/* the size of the logically next block */
	size_t next_block_size;
	/* if there is enough space to create a new block, we split the block we are removing */
	if (size - (requested_size + 16) >= 32)
	{
		split_block(block, size, requested_size, c_list);
	}
	else
	{
		/* use front and back pointers in the block to find the logically next and previous blocks in the list */
		next_block = (void*)mem_read((char*) block + 8,8); 	
		previous_block = (void*)mem_read((char*)block + (size - 16), 8);
		/* update the block we are removing's size so the last bit reads one, this way we know it is allocated */
		mem_write(block, (uint64_t)(size | 1), 8);
		mem_write((char*)block + (size)-8, (uint64_t)(size|1), 8);
		/*if the block is the only one in the list, the root-pointer is set to zero, signifing the list is now empty*/
		if (previous_block == 0 && next_block == 0)
		{
			root_list[c_list].first_block = next_block;
			return;
		}
		/*if the block is the last one in the list, we only update the previous block's front pointer */
		if(previous_block != 0 && next_block == 0)
		{
			mem_write((char*)previous_block+8, 0, 8);			
			return;
		}	
		/* if the block is the first block but there are others in the list, we update the root to point to the 
 		* next block, and also set the next block's back pointer to be zero */ 
		if(previous_block == 0 && next_block!= 0)
		{	
			root_list[c_list].first_block = next_block;
			next_block_size = (size_t)mem_read(next_block,8);
			mem_write((char*)next_block + next_block_size-16, 0, 8);
			return; 
		}
		/* if the block is in the middle of the list somewhere, we update the previous block's front pointer so it points
 		* to the next block, and the next block's back pointer so that it points to the previous block */ 
		if(previous_block != 0 && next_block != 0)
		{
			mem_write((char*) previous_block + 8, (uint64_t)next_block, 8);
			next_block_size = (size_t)mem_read(next_block,8);
			mem_write((char*)next_block + next_block_size-16, (uint64_t)previous_block, 8);
			return;
		}
	}
}
/* 
 * examines the physically next block in the heap, and if it is free we merge it with the block we are freeing 
 */
size_t coalesce(void * ptr, size_t size)
{
	/* the physically next block in the heap */
	void * next_block_address = (char*)ptr + (size&-2);
	/* the next block's front and back pointers (in the free list it is part of */
	void * next_block_back_ptr;
	void * next_block_fwrd_ptr;
	/* the next block's size */
	size_t next_block_size;
	/* the size of the block pointed to by the fowared pointer in the 'next_block'
 	* used to find this block's back pointer */	 
	size_t next_block_fwrd_ptr_size;
	/* the combined size of the merged blocks */
	size_t combined_size;
	int i;
	int c_list= NUM_FREE_LISTS-1;
	/* checks if the the block we are freeing is the last in the heap, if so we can't merge it with anything */
	if(next_block_address > mem_heap_hi())
	{
		return size&-2;
	}
	/* reads the next block's size and uses it to compute which free list the block is a part of */
	next_block_size = (size_t)mem_read(next_block_address, 8);
	for(i = 0; i < NUM_FREE_LISTS-1; i ++)
	{
		if(next_block_size-16 < root_list[i].max_size)
		{
			c_list = i;
			break;
		}
	}
	/* uses the last bit of the next block's size to check if it is free or not */
	if((next_block_size &1) ==0)
	{
		/* if it is free we calculate its front and back pointers */
		next_block_fwrd_ptr = (void*)mem_read((char*)next_block_address + 8, 8);
		next_block_back_ptr =(void*) mem_read((char*)next_block_address + next_block_size - 16, 8);
		/* if the next_block is logically the first in its free list then the block it points to with 
 		* its foward pointer becomes the first in the list */	 
		if(next_block_back_ptr == 0)
		{
			root_list[c_list].first_block = next_block_fwrd_ptr;
		}
		/* otherwise the block the back pointer points to's foward pointer is updated so that it now points to the front pointer
 		* in other words, the previous block now points 'through' the block we are merging to the block after it in the free list */ 		
		else
		{
			mem_write((char*)next_block_back_ptr + 8, (uint64_t)next_block_fwrd_ptr, 8);
		}
		/* if the block we are merging is not the logically last one in the free list, we set the block ahead of it's back pointer to 
 		* point to the previous block, in other words the next block points 'through' the block we are merging to the block before it 
 		* in the free list */
		if(next_block_fwrd_ptr != 0)
		{				
			next_block_fwrd_ptr_size = (size_t)mem_read(next_block_fwrd_ptr, 8);
			mem_write((char*)next_block_fwrd_ptr + next_block_fwrd_ptr_size -16, (uint64_t)next_block_back_ptr, 8);
		}
		/* write the combined size to the header and footer of the newly created merged block */
		combined_size = (size&-2) + next_block_size;
		return combined_size;
	}
	/* if we cannot coalesce, just return the actual size of the block by switching the last bit in the size field from a one to a zero*/
	return size&-2;
}
/*
 * coalesces with the physically previous block in the heap, if coalescing cannot occur we simply return the size of the block we are trying to free 
 */
size_t coalesce_previous_block(void * ptr, size_t size, void ** address_pointer)
{
	/* fields for the physically previous block's size, as well as its pointers and start address */
	size_t previous_block_size;
	size_t previous_block_fwrd_ptr_size;
	size_t combined_size;
	void * previous_block_address;
	void * previous_block_fwrd_ptr;
	void * previous_block_back_ptr;
	int i;
	int c_list = NUM_FREE_LISTS-1;
	/* if the block we are trying to merge is the physically first one in the heap we can't merge*/
	if((char*)ptr - 8 < (char*)mem_heap_lo() + 168)
	{
		return size;
	}
	/* read the previous block's size and use it to compute which free list it is a part of */
	previous_block_size = mem_read((char*)ptr-8, 8);
	for( i = 0;i <NUM_FREE_LISTS-1; i ++)
	{
		if(previous_block_size - 16 < root_list[i].max_size)
		{
			c_list = i;
			break;
		}
	}
	/* checks if the previous block is free using the final bit of the size*/
	if((previous_block_size &1) ==0)
	{
		/* calculates the previous blocks strating address using its size as well as its pointers */
		previous_block_address = (char*)ptr - previous_block_size;
		previous_block_fwrd_ptr = (void*)mem_read((char*)previous_block_address + 8, 8);
		previous_block_back_ptr = (void*)mem_read((char*)ptr - 16, 8);
		*address_pointer = previous_block_address;
		/* updates the previous block's pointers and those of the blocks it points to in a similar way to what we
 		* did in the coalesce function */ 
		if(previous_block_back_ptr == 0)
		{
			root_list[c_list].first_block = previous_block_fwrd_ptr;
		}
		else
		{
			mem_write((char*)previous_block_back_ptr + 8, (uint64_t)previous_block_fwrd_ptr, 8);
		}
		/* this time, we make the back pointer of the block that the previous block's foward pointer points to, point to the previous block's 
 		* back pointer, this is the opposite of what we did in foward coalescing */  
		if(previous_block_fwrd_ptr != 0)
		{	
			previous_block_fwrd_ptr_size = (size_t)mem_read(previous_block_fwrd_ptr, 8);
			mem_write((char*)previous_block_fwrd_ptr + previous_block_fwrd_ptr_size - 16, (uint64_t)previous_block_back_ptr, 8);
		}
		/* writes the combined size to the header and footer of the newly created block */
		combined_size = size + previous_block_size;
		mem_write(previous_block_address, (uint64_t)combined_size, 8);
		mem_write((char*)previous_block_address + combined_size - 8, (uint64_t)combined_size, 8);
		return combined_size;
	}
	/* if the block is not free we just return the size we were passed */		
	return size;
}
/*
 * If we are alloacting a block with extra space, we split the block into two seperate ones
 * we cal free to add the newly formed block to the free list
 */
void split_block(void * block, size_t block_size, size_t requested_size, int c_list)
{
	/* the pointers of the block we are trying to split */
	void * fwrd_ptr = (void *)mem_read((char*)block+8,8);
	void * back_ptr = (void *)mem_read((char*)block + block_size - 16, 8);
	/* this will point to the beginning of the newly created free block */
	void * new_free_block;
	/* the size of the block we are going to allocate */
	size_t new_allocated_block_size = requested_size + 16;
	/* the size of the new free block */
	size_t new_free_block_size = block_size - new_allocated_block_size;
	/* the size of the block being pointed to with the foward pointer, needed to change the pointed-to block's back pointer */
 	size_t next_in_list_size;	
	/* calculates the starting address of the newly freed block, then writes the new size data to the header and footer of both
 	* the block we will allocate and this newly freed one */ 
	new_free_block = (char*)block + new_allocated_block_size;
	/* the allocated block will need the last bit of its size to be one so we know it's allocated */
	mem_write(block, (uint64_t)new_allocated_block_size|1, 8);
	mem_write((char*)block + new_allocated_block_size - 8, (uint64_t)new_allocated_block_size|1, 8);
	mem_write(new_free_block, (uint64_t)new_free_block_size, 8);
	mem_write((char*)new_free_block + new_free_block_size - 8, (uint64_t)new_free_block_size,8);
	/* update the pointers of the free block */
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
	/* calls free on the newly created free block to add it to the free list */
	free((char*)new_free_block+8);
}

/*
 * loops through the slab lists to find an open position in a slab, if no such position can be found then a new slab is created 
 */
void* find_slab(size_t size)
{
	/* the address of the slab are examining */
	void* slab = NULL;
	/* used to see when we have looped through the whole slab list */
	void* checking_slab = NULL;
	/* the address of a new slab if we maek one */
	void* new_slab = NULL;
	/* the slab list of the block we are examining as well as the size of the slabs in said list and the size of the blocks in those slabs */
	int list;
	size_t slab_size;
	size_t block_size;
	/* the bitmap of each slab */
	uint64_t bitmap;
	/* used to update the bitmap */
	uint64_t temp_bitmap;
	int i;
	int j;
	/* will have the value of a certain bit from the bitmap so we can see if the space in the slab is free */
	int allocated;
	/* uses the requested size to see which list we should loop through */
	if(size == 16)
	{
		list = 0;
		slab_size = 528;
		block_size = 16;
	}
	else
	{
		list = 1;
		slab_size = 1040;
		block_size = 32;
	}
	/* begin searching at the slab that was freed last */
	slab = slab_lists[list].last_freed;	
	/* if the slab list is not empty */
	if(slab != 0)
	{	
		/* loop until we have examined ever block, that is to say, until we try examining last freed a second time */
		while(checking_slab != slab_lists[list].last_freed)
		{
			/* read the bitmap from the slab */
			bitmap = mem_read(slab, 8);
			/* if the slab has an empty posiiton */
			if(bitmap != 0xffffffff)
			{
				/* first loop examining the bytes */
				for(i = 28; i >=0; i = i - 4)
				{
					/* if a byte is not equal to f, that means there must be an open slot in it */
					if((bitmap >>i) != 0xf)
					{
						/* now loop examining the bits of the selected byte */
						for(j = i + 3; j >= i; j = j -1)
						{
							/* isolate a bit by shifting it to the right and anding it withe one */
							allocated = (bitmap >> j) & 1;
							/* if the bit is zero, there must be a space in the slab, update the bitmap and return the address 
 							* represented by the bit */ 
							if(allocated == 0)
							{
								temp_bitmap = 1 << (j); 
								bitmap = bitmap | temp_bitmap;
								mem_write(slab, bitmap, 8);
								add_slab_cache(slab);
								return (char*)slab + 16 + (31 - j)*block_size;
							}
						}
					}	
				}
			}
			/* search the next slab in the list, if we reach the end of the list, go back to the first slab */
			slab = (void*)mem_read((char*)slab + 8, 8);
			if(slab == 0)
			{
				slab = slab_lists[list].first_slab;
			}
			/* use checking slab to see when we reach the last freed slab again */
			checking_slab = slab;
		}
		/* if we examine all the slabs, we create a new one and add it to the slab cache */
		new_slab = create_slab(slab_size);	
		mem_write((char*)new_slab + 8, (uint64_t)slab_lists[list].first_slab, 8);
		slab_lists[list].first_slab = new_slab;
		slab_lists[list].last_freed = new_slab;
		add_slab_cache(new_slab);
		return (void*)(char*)new_slab+16;
			
	}
	else
	{
		/* if the slab list list is empty, we create a new one and add it to the list as well as the slab cache */
		new_slab = create_slab(slab_size);
		slab_lists[list].first_slab = new_slab;
		slab_lists[list].last_freed = new_slab;
		add_slab_cache(new_slab);
		return (void*)(char*)new_slab + 16;
	}
	return NULL;
}
/*
 * creates a new slab of a specified size, and initializes its bitmap to say that the first slot has been filled
 * uses malloc to get the space for the new slab
 */
void* create_slab(size_t size)
{
	void* slab_address;
	slab_address = malloc(size);
	mem_write(slab_address, 0x80000000, 8);
	mem_write((char*)slab_address + 8, 0, 8);
	return slab_address;
}
/*
 * frees a slot in a slab and updates the bitmap accordingly, if the slab becomes empty, we call free on the whole thing 
 * so it becomes an ordinary free block in one of the free lists
 */
bool free_slab(void* ptr)
{
	/* poiinter to the slab ptr is inside of */
	void* slab; 
	/* the previous slab logically in the free slab list we are examining */
	void* prev_slab = NULL;
	/* the size of the whole slab as well as the blocks inside of the slab */
	size_t slab_size;
	size_t block_size;
	int i;
	/* this array is used to store information returned when we search the slab cache */
	uint64_t return_array[3];

	/* search the slab cache before just looping  */
	if(search_slab_cache(ptr, return_array) == true)
	{	
		/* if the slab was found in the slab cache then we use the information in the return array to determine
 		* what the block size of the slab is, and what the slab's starting address is, return array[2] also stores this offset
 		* but is used when updateing the clock data for the slab's cache entry */ 
		slab = (void*)mem_read((char*)mem_heap_lo() + return_array[0] , 8);
		i = return_array[1];
		if(i == 0)
		{
			block_size = 16;
		}
		else
		{
			block_size = 32;
		}
		/* call remove slab to free up the space associated with ptr, or to free the whole slab */
		return remove_slab(ptr, slab, (void*)1, i, block_size, return_array[2]);
	}
	/* if the slab is not in the cache we can loop through both slab lists till we find the one which contains ptr */
	for(i = 1; i >= 0; i= i -1)
	{ 
		/* based on which list we're examining we set the slab size and block size accordingly */
		if(slab_lists[1].first_slab == 0)
		{
			i = 0;
		}
		prev_slab = 0;
		if(i == 0)
		{
			slab_size = 528;
			block_size = 16;
		}
		else
		{
			slab_size = 1040;
			block_size = 32;
		}
		slab = slab_lists[i].first_slab;
		/* while we have not reached end of the slab list */
		while(slab != 0)
		{
			/* if ptr is inside of the slab we add that slab to the slab cache and call remove slab on the found slab*/
			if(ptr > slab && (char*)ptr < ((char*)slab + slab_size))
			{
				add_slab_cache(slab);
				return remove_slab(ptr, slab, prev_slab, i, block_size, 300);
			}
			/* otherwise continue looping */
			else
			{
				prev_slab = slab;
				slab = (void*)mem_read((char*)slab + 8, 8);
			}	
		}
	}	
	return false;
}
/*
 * called by realloc to figure out if a given ptr is in a slab list, returns zero if the ptr is not in a slab
 * or the block size (16 or 32) if the ptr is in a slab
 */
size_t find_list(void* ptr)
{
	/* more or less the same searching algorithm from free */
	int i = 0;
	void* slab;
	size_t slab_size;
	size_t block_size;
	for(i = 0; i < 2; i ++)
	{	
		if(slab_lists[0].first_slab == 0)
		{
			i = 1;
		}
		if(i == 0)
		{
			slab_size = 528;
			block_size = 16;
		}
		else
		{
			slab_size = 1040;
			block_size = 32;
		}
		slab = slab_lists[i].first_slab;			
		while(slab != 0)
		{
			if(ptr > slab && (char*)ptr < (char*)slab + slab_size)
			{
				return block_size;
			}
			slab = (void*)mem_read((char*)slab + 8, 8);
		}
	}
	return 0;
}
/*
 * adds a slab to the slab cache, the cache occupies the lower 168 bytes of the heap and uses a clock to track calls to it
 * the cahce is fully associative and uses an LRU replacement policy
 */
bool add_slab_cache(void* ptr)
{
	cache_adds ++;
	/* stores the first heap address for easy access */
	void* heap_lo = mem_heap_lo();	
	/* the slab address stored at a certain position in the heap*/
	void* current_slab;
	int j;
	/* reads the clock value from the heap */
	uint64_t clock = mem_read(mem_heap_lo(), 8);
	clock ++;
	uint64_t clock_reading;
	/* values to track the oldest cache entry */
	uint64_t lowest_reading = (uint64_t)-1;
	void* lowest_index = 0;
	/* loops through all the cache entries */
	for(j = 8; j < 88; j += 8)
	{
		/* reads the clock reading associated with each cache entry (the time it was added) and gets the slab stored at said entry */
		clock_reading = mem_read((char*) heap_lo + j, 8);
		current_slab = (void*)mem_read((char*)heap_lo + j +80, 8);
		/* if the slab we are trying to add is already in the cache we just update its clock data */
		if(current_slab == ptr)
		{
			mem_write((char*)heap_lo + j, clock, 8);
			return true;
		}
		/* if an older entry is found we store that entries index */
		if(clock_reading < lowest_reading)
		{
			lowest_reading = clock_reading;
			lowest_index = (char*)heap_lo + j;
		}
	}
	/* replace the oldest entry with the new slab */
	mem_write(lowest_index, clock, 8);
	mem_write((char*)lowest_index + 80, (uint64_t)ptr, 8);
	mem_write(mem_heap_lo(), clock, 8);
	return true;
}
/*
 * searches through the slab cache to see if a requested pointer is in one of the slabs stored in the cache 
 * returns true if yes, otherwise returns false
 */
bool search_slab_cache(void* ptr, uint64_t* return_array)
{
	/* similar variables were used in add_slab_cache */
	void* heap_lo = mem_heap_lo();
	uint64_t clock = mem_read(heap_lo, 8);	
	clock ++;
	int j;
	void* slab;
	size_t slab_size;
	/* loops through all the cache entries */
	for(j = 88; j < 168; j += 8)
	{
		slab = (void*)mem_read((char*)heap_lo + j, 8);
		/* if the entry isn't empty */
		if(slab != 0)
		{
			/* read the slab size and use it to see if ptr is inside of the slab */
			slab_size = mem_read((char*)slab - 8, 8);
			if(ptr > slab && (char*)ptr < ((char*)slab-8) + slab_size)
			{
				/* if the ptr is in the slab update the values in the return array and return true */
				return_array[0] = j;
				if(slab_size <= 600)
				{
					return_array[1] = 0;
				}
				else
				{
					return_array[1] = 1;
				}
				return_array[2] = j;
				mem_write((char*)heap_lo + j - 80, clock, 8);
				mem_write(mem_heap_lo(), clock, 8);
				return true;
			}	
		}		
	}	
	return false;
}
/*
 * either updates a bit in the bitmap to say that a new space has opened up, or completely frees the slab if the bitmap is completely freed up
 * returns true in either case 
 */
bool remove_slab(void* ptr, void* slab, void* prev_slab, int i, size_t block_size, uint64_t cache_index)
{
	/* slab index is the bit that refers to ptr*/ 
	uint64_t slab_index;
	uint64_t bitmap;
	uint64_t temp_bitmap;
	/* temp slab and other temp slab will be used to store data from the free slab list */
	void* temp_slab;
	void* other_temp_slab;
	/* logically the next slab in the free list, pointed to by the slabs front pointer*/
	void* next_slab;
	/* if we got the slab from the cache we need to know where it is in the free list in the event that we remove it 
 	* this variable is used when looping through the list to find the previous slab logically to the one we are freeing */
	void* loop_slab;
	/* updates the bitmap */
	slab_index = ((uint64_t)ptr - ((uint64_t)slab + 16))/block_size;
	bitmap = (uint64_t)mem_read(slab, 8);
	temp_bitmap = 0x80000000 >> slab_index;
	temp_bitmap = ~temp_bitmap;
	bitmap = bitmap & temp_bitmap;	
	/* if the slab is completely empty we can free the whole slab, and then update the free slab list */
	if(bitmap == 0)
	{
		/* if the slab was found in the cache we need to find the slab before it in the free list */
		if(prev_slab == (void*)1)
		{
			prev_slab = 0;
			loop_slab = slab_lists[i].first_slab;
			while(loop_slab != 0)
			{
				if(loop_slab == slab)
				{
					break;
				}
				prev_slab = loop_slab;
				loop_slab = (void*)mem_read((char*)loop_slab + 8, 8);
			}		
		}
		/* if the slab came from the cache we need to remove it from the cache */
		if(cache_index != 300)
		{
			remove_from_cache(cache_index);
		}
		/* updates the free list, and also calls free on the slab, we need to temporaily store the first slabs of both lists so that we can set the values
 		* to zero when we call free, otherwise we would waste time looking for a slab */ 
		temp_slab = slab_lists[i].first_slab;
		other_temp_slab = slab_lists[abs(i-1)].first_slab;
		next_slab = (void*)mem_read((char*)slab + 8, 8);
		slab_lists[0].first_slab = 0;
		slab_lists[1].first_slab = 0;
		free((char*)slab);
		slab_lists[i].first_slab = temp_slab;
		slab_lists[abs(i-1)].first_slab = other_temp_slab;		
		if(prev_slab == 0)
		{
			slab_lists[i].first_slab = next_slab;	
		}
		else
		{
			mem_write((char*)prev_slab + 8, (uint64_t)next_slab, 8);
		}	
		slab_lists[i].last_freed = slab_lists[i].first_slab;
		return true;
	}
	/* if the slab was not freed, we update its bitmap field */
	mem_write(slab, bitmap, 8);
	slab_lists[i].last_freed = slab;
	return true;
}
/*
 * removes an entry from the cache using a specified cache index, simply sets the entry equal to zero as well as the clock entry associated with it
 */
void remove_from_cache(uint64_t cache_index)
{	
	void* heap_lo = mem_heap_lo();
	mem_write((char*)heap_lo + cache_index, 0, 8);
	mem_write((char*)heap_lo + cache_index - 80, 0, 8);
}
/*
 * prints the contents of the slab cache
 */
void print_cache()
{
	uint64_t index = (uint64_t)mem_heap_lo() + 88;
	uint64_t i;
	printf ("cache:\n");
	for(i = index; i < index + 80; i += 8)
	{
		printf ("%p\n", (void*)mem_read((void*)i, 8));
	}
}
