/*
 * mm.c
 *
 * This is an implementation for a dynamic memory allocator. Free blocks are stored in 8 segregated free lists. Free blocks are coalesced 
 * when possible, and allocated blocks are split if there is extra space. Blocks are made up of a header, a footer, and at least a 16 byte
 * payload. The payload area is used to store pointers for the free linked lists when the block is free.
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
/*#define DEBUG*/

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
#define NUM_FREE_LISTS 8
/* root structure: points to the first element of a free list and also tracks that lists maximum block size*/
typedef struct root
{
	void * first_block;
	size_t max_size;
}root;
/* slab root structure: points to first element in a slab free list as well as to the last slab that was freed but is still in the list*/
/* global arrays containing all free roots and slab roots*/
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
 * creates a heap offset of 168 to be used for the slab cache
 * initializes the free lists and slab free lists
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
 * malloc: calls find free block and returns its return value
 */
void* malloc(size_t size)
{	
	void * block;
	block = find_free_block(size);
	#ifdef DEBUG
	mm_checkheap(173);
	#endif
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
	/* gets size of old block from oldptr*/	
	old_size = (mem_read((char*)oldptr-8, 8)-16)&-2;
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
    return align(ip) - 8 == ip;
}

/*
 * mm_checkheap
 */
bool mm_checkheap(int lineno)
{
#ifdef DEBUG
	printf("Entering checkheap at line %d\n",lineno);
	/* the first block is located at an offset of 8 */
	void * starting_address = (char*)mem_heap_lo()+8;
	int i;
	/* will be used to loop through the free list */
	void * free_block;
	/* the current block we are examining */
	void * current_block;
	size_t current_block_size= 0;
	size_t free_size=0;
	/* tracks the total amount of allocated bytes in the heap at a certain moment */
	size_t allocated_size=0;
	/* the number of free blocks in the heap and the number of blocks in total */
	int num_free_blocks= 0;
	int num_blocks= 0;
	/* is free is set to zero if a block is actually free */
	int is_free = 1;
	/* checks if the previous block was free, used to see if coalescing occurs when it should */
	int prev_is_free = 1;
	int c_list = NUM_FREE_LISTS -1;
	int c_list_check = NUM_FREE_LISTS -1;
	current_block = starting_address; 
	dbg_printf("Entering while loop\n");
	/* loop through the entire heap block by block */
	while(current_block < mem_heap_hi())
	{
		num_blocks ++;	
		current_block_size = mem_read(current_block, 8);
		prev_is_free = is_free;
		is_free = current_block_size & 1;
		/* when a free block is found we loop through the free lists to see if it is in one of them*/
		if(is_free == 0)
		{
			/* increment the free block counter*/
			num_free_blocks ++;
			free_size += current_block_size;
			/* begin looping through the free list */
			for(i = 0; i < NUM_FREE_LISTS; i ++)
			{
				/* reset the c_list values so they are not differnet from the last time we did this search */
				c_list = NUM_FREE_LISTS -1;
				c_list_check = NUM_FREE_LISTS -1;
				free_block = root_list[i].first_block;
				while(free_block != 0)
				{
					/* when we find the block in one of the lists we break and store the list it was in in c_list*/
					if(free_block == current_block)
					{
						c_list = i;
						i = 100;
						break;
					}
					free_block = (void*)mem_read((char*)free_block + 8, 8);
				}
				if(i == 100){
	`				/* now we loop through the free lists and see which one the block should fall into based on its size */
					for(i = 0; i < NUM_FREE_LISTS -1; i ++)
					{
						if((current_block_size &-2) <= root_list[i].max_size)
						{
							c_list_check = i;
							break;
						}
					}
					/* compare the list it was found in with the list we expect it to be in*/
					if(c_list_check != c_list)
					{
						dbg_printf("block in wrong free list\n");
						dbg_prinTF("c_list: %d\n", c_list);
						dbg_printf("check_c_list: %d\n", c_list_check);
						dbg_printf("block_size: %zu\n", current_block_size &-2);
					}
					i = 100;
					break;
				}
			}
			if(i != 100)
			{
				printf("Error: a free block: %p wasn't in the free list\n", current_block);			
			}
		}
		else
		{
			allocated_size += current_block_size;
		}
		/* checks if coalescing occured between adjacent free blocks */
		if(prev_is_free == 0 && is_free == 0)
		{
			printf("Error: two adjacent free blocks didn't coalesce\n");
			dbg_printf("current block size: %zu\n", current_block_size);
			assert(1 == -1);
		}
		/* checks if each block is aligned (they should all be aligned to 16 with an offset of 8, so aligned to 24 */
		if(!aligned(current_block)){
			printf("Error: address not aligned in %p, line %d\n",current_block,lineno);
		}
		/* checks to see if header and footer data are the same */
		if(current_block_size!=mem_read((char*)current_block + ((current_block_size&-2) - 8),8)){
			printf("Error: Footer and Header not the same in %p, line%d\n",current_block,lineno);
		}
		current_block = (char*)current_block + (current_block_size & -2);
	}
	// dbg_printf ("total blocks: %d\n", num_blocks);
	// dbg_printf ("free blocks: %d\n", num_free_blocks);
	// dbg_printf ("free bytes: %zu\n", free_size);
	// dbg_printf ("allocated bytes: %zu\n", allocated_size);
	// dbg_printf ("utilization: %5.2f\n",100.0 * (double)allocated_size /(free_size + allocated_size));
    	return true;
#endif /* DEBUG */
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
		root_list[0].max_size = 64;
		root_list[1].max_size = 128;
		root_list[2].max_size = 256;
		root_list[3].max_size = 512;
		root_list[4].max_size = 1024;
		root_list[5].max_size = 2048;
		root_list[6].max_size = 4096;
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
	/* use front and back pointers in the block to find the logically next and previous blocks in the list */
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
	if((char*)ptr - 8 < (char*)mem_heap_lo() + 8)
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

