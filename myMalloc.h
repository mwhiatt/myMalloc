#ifndef MY_MALLOC_H
#define MY_MALLOC_H

#include <stdbool.h>
#include <sys/types.h>

#define RELATIVE_POINTERS true

#ifndef ARENA_SIZE
// If not specified at compile time use the default arena size
#define ARENA_SIZE 4096
#endif

#ifndef N_LISTS
// If not specified at compile time use the default number of free lists
#define N_LISTS 59
#endif

#define ALLOC_HEADER_SIZE (sizeof(header) - (2 * sizeof(header *)))

/* The minimum size request the allocator will service */
#define MIN_ALLOCATION 8

/**
 * enum for state of block
 */
enum state {
  UNALLOCATED = 0,
  ALLOCATED = 1,
  FENCEPOST = 2,
};

/*
 * Header struct allows for quick navigation of the free list at 
 * slight overhead cost.
 */
typedef struct header {
  size_t size_state;
  size_t left_size;
  union {
    // Used when the object is free
    struct {
      struct header * next;
      struct header * prev;
    };
    // Used when the object is allocated
    char data[0];
  };
} header;

// Getters and Setters

static inline size_t get_size(header * h) {
	return h->size_state & ~0x3;
}

static inline void set_size(header * h, size_t size) {
	h->size_state = size | (h->size_state & 0x3);
}

static inline enum  state get_state(header *h) {
	return (enum state) (h->size_state & 0x3);
}

static inline void set_state(header * h, enum state s) {
	h->size_state = (h->size_state & ~0x3) | s;
}

static inline void set_size_and_state(header * h, size_t size, enum state s) {
	h->size_state=(size & ~0x3)|(s &0x3);
}

#define MAX_OS_CHUNKS 1024

header * get_right_header(header * h);

/*
 * global variables
 */
extern void * base;
extern header freelistSentinels[];
extern char freelist_bitmap[];
extern header * osChunkList[];
extern size_t numOsChunks;

#endif // MY_MALLOC_H
