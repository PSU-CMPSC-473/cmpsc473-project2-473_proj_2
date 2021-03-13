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
#define NUM_FREE_LISTS 6
#define NUM_SLAB_LISTS 2
typedef struct root
{
	void * first_block;
	size_t max_size;
}root;
typedef struct slab_root
{
	void* first_slab;
	void* last_freed;
}slab_root;
slab_root slab_lists[NUM_SLAB_LISTS];
root root_list[NUM_FREE_LISTS];
int number_of_ops;
float average_malloc_time;
clock_t average_free_time;
clock_t total_m_time;
clock_t total_f_time;
int mallocs;
int frees;
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
 * malloc
 */
void* malloc(size_t size)
{	
	/*clock_t start_time = clock()/CLOCKS_PER_SEC;
	clock_t end_time;*/
	number_of_ops ++;
	mallocs ++;
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
	/*end_time = clock()/CLOCKS_PER_SEC;
	total_m_time += (end_time - start_time);
	average_malloc_time = (float)total_m_time / (float)mallocs;
	if(number_of_ops >= 67000)
	{
		printf ("total time in malloc: %f\n", (float)total_m_time);
		printf ("average time per malloc: %f\n", (float)average_malloc_time);
	}*/	
	return block;
}


void free(void* ptr)
{
	number_of_ops ++;
	if(slab_lists[0].first_slab != 0 || slab_lists[1].first_slab != 0)
	{
		if(free_slab(ptr))
		{
			return;
		}
	}
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
	/*mm_checkheap(194);*/	
	return;
}

/*
 * realloc mallocs a new block on the heap
 * and frees up the old block
 */
void* realloc(void* oldptr, size_t size)
{
	void * new_block;
	size_t old_size = 0;
	size_t smaller_size;
	uint64_t i;

	if(slab_lists[0].first_slab != 0 || slab_lists[1].first_slab != 0)
	{
		old_size = find_list(oldptr);	
	}
	if(old_size == 0)
	{
		old_size = (mem_read((char*)oldptr-8, 8)-16)&-2;
	}
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
				printf ("a free block: %p wasn't in the free list\n", current_block);			
				assert(1 == -1);
			}
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
	/*printf ("total blocks: %d\n", num_blocks);
	printf ("free blocks: %d\n", num_free_blocks);
	printf ("free bytes: %zu\n", free_size);
	printf ("allocated bytes: %zu\n", allocated_size);
	printf ("utilization: %5.2f\n",100.0 * (double)allocated_size /(free_size + allocated_size));*/
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
       	
	if(aligned_size <= 32)
	{
		return find_slab(aligned_size);
	}
	for(i = 0; i < NUM_FREE_LISTS-1;i ++)
	{
		if(aligned_size <= root_list[i].max_size)
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
	if (size - (requested_size + 16) >= 48)
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
		next_block_fwrd_ptr = (void*)mem_read((char*)next_block_address + 8, 8);
		next_block_back_ptr =(void*) mem_read((char*)next_block_address + next_block_size - 16, 8);
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

void* find_slab(size_t size)
{
	void* slab = NULL;
	void* checking_slab = NULL;
	void* new_slab = NULL;
	int list;
	size_t slab_size;
	size_t block_size;
	uint64_t bitmap;
	uint64_t temp_bitmap;
	int i;
	int j;
	int allocated;
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
	
	slab = slab_lists[list].last_freed;	
	if(slab != 0)
	{	
		while(checking_slab != slab_lists[list].last_freed)
		{
			bitmap = mem_read(slab, 8);
			if(bitmap != 0xffffffff)
			{
				for(i = 28; i >=0; i = i - 4)
				{
					if((bitmap >>i) != 0xf)
					{
						for(j = i + 3; j >= i; j = j -1)
						{
							allocated = (bitmap >> j) & 1;
							if(allocated == 0)
							{
								temp_bitmap = 1 << (j); 
								bitmap = bitmap | temp_bitmap;
								mem_write(slab, bitmap, 8);
								return (char*)slab + 16 + (31 - j)*block_size;
							}
						}
					}	
				}
			}
			slab = (void*)mem_read((char*)slab + 8, 8);
			if(slab == 0)
			{
				slab = slab_lists[list].first_slab;
			}
			checking_slab = slab;
		}
		new_slab = create_slab(slab_size);	
		mem_write((char*)new_slab + 8, (uint64_t)slab_lists[list].first_slab, 8);
		slab_lists[list].first_slab = new_slab;
		slab_lists[list].last_freed = new_slab;
		return new_slab+16;
			
	}
	else
	{
		new_slab = create_slab(slab_size);
		slab_lists[list].first_slab = new_slab;
		slab_lists[list].last_freed = new_slab;
		return new_slab + 16;
	}
	return NULL;
}
void* create_slab(size_t size)
{
	void* slab_address;
	slab_address = malloc(size);
	mem_write(slab_address, 0x80000000, 8);
	mem_write((char*)slab_address + 8, 0, 8);
	return slab_address;
}
bool free_slab(void* ptr)
{
	void* slab; 
	void* prev_slab = NULL;
	void* next_slab;
	void* temp_slab;
	void* other_temp_slab;
	uint64_t slab_index = 0;
	uint64_t bitmap= 0;
	uint64_t temp_bitmap= 0;
	size_t slab_size;
	size_t block_size;
	int i;
	for(i = 1; i >= 0; i= i -1)
	{ 
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
		while(slab != 0)
		{
			if(ptr > slab && (char*)ptr < ((char*)slab + slab_size))
			{
				/*printf ("we got im'\n");
				printf ("ptr: %p\n", ptr);
				printf ("slab: %p\n", slab);*/
				slab_index = ((uint64_t)ptr - ((uint64_t)slab + 16))/block_size;
				/*printf ("slab_index: %lu\n", slab_index);*/ 		
				bitmap = (uint64_t)mem_read(slab, 8);
				temp_bitmap = 0x80000000 >> slab_index;
				/*printf ("bitmap: %lx\n", bitmap);
				printf ("temp_bitmap: %lx\n", temp_bitmap);*/
				temp_bitmap = ~temp_bitmap;
				bitmap = bitmap & temp_bitmap;	
				/*printf ("not temp bitmap: %lx\n", temp_bitmap);
				printf ("new bitmap: %lx\n", bitmap);*/
				if(bitmap == 0)
				{
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
				mem_write(slab, bitmap, 8);
				slab_lists[i].last_freed = slab;
				return true;
			}
			else
			{
				prev_slab = slab;
				slab = (void*)mem_read((char*)slab + 8, 8);
			}	
		}
	}	
	return false;
}
size_t find_list(void* ptr)
{
	int i = 0;
	void* slab;
	size_t slab_size;
	size_t block_size;
	for(i = 0; i < 2; i ++)
	{	
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
