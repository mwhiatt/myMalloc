#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "myMalloc.h"


static pthread_mutex_t mutex;
header freelistSentinels[N_LISTS];
header * lastFencePost;
void * base;
header * osChunkList [MAX_OS_CHUNKS];
size_t numOsChunks = 0;

/*
 * direct the compiler to run the init function before running main
 * this allows initialization of required globals
 */
static void init (void) __attribute__ ((constructor));

// Helper functions for manipulating pointers to headers
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off);
static inline header * get_left_header(header * h);
static inline header * ptr_to_header(void * p);

// Helper functions for allocating more memory from the OS
static inline void initialize_fencepost(header * fp, size_t left_size);
static inline void insert_os_chunk(header * hdr);
static inline void insert_fenceposts(void * raw_mem, size_t size);
static header * allocate_chunk(size_t size);

// Helper functions for freeing and deleting a block
static inline void deallocate_object(void * p);
static inline header * allocate_object(size_t raw_size);

static void init();

static inline header * get_header_from_offset(void * ptr, ptrdiff_t off) {
	return (header *)((char *) ptr + off);
}

header * get_right_header(header * h) {
	return get_header_from_offset(h, get_size(h));
}

inline static header * get_left_header(header * h) {
  return get_header_from_offset(h, -h->left_size);
}

inline static void initialize_fencepost(header * fp, size_t left_size) {
	set_state(fp,FENCEPOST);
	set_size(fp, ALLOC_HEADER_SIZE);
	fp->left_size = left_size;
}

inline static void insert_os_chunk(header * hdr) {
  if (numOsChunks < MAX_OS_CHUNKS) {
    osChunkList[numOsChunks++] = hdr;
  }
}

inline static void insert_fenceposts(void * raw_mem, size_t size) {
  // Convert to char * before performing operations
  char * mem = (char *) raw_mem;

  // Insert a fencepost at the left edge of the block
  header * leftFencePost = (header *) mem;
  initialize_fencepost(leftFencePost, ALLOC_HEADER_SIZE);

  // Insert a fencepost at the right edge of the block
  header * rightFencePost = get_header_from_offset(mem, size - ALLOC_HEADER_SIZE);
  initialize_fencepost(rightFencePost, size - 2 * ALLOC_HEADER_SIZE);
}

static header * allocate_chunk(size_t size) {
  void * mem = sbrk(size);
  
  insert_fenceposts(mem, size);
  header * hdr = (header *) ((char *)mem + ALLOC_HEADER_SIZE);
  set_state(hdr, UNALLOCATED);
  set_size(hdr, size - 2 * ALLOC_HEADER_SIZE);
  hdr->left_size = ALLOC_HEADER_SIZE;
  hdr->prev = NULL;
  hdr->next = NULL;
  return hdr;
}

static inline header * allocate_object(size_t raw_size) {
  //An allocation of 0 bytes should return the NULL pointer for determinism
  if (raw_size == 0) {
    return NULL;
  }

  //round up size, get totalSize of the object we need
  size_t size8 = ((raw_size+7)/8)*8;
  if (size8 < 16) {
    size8 = 16;
  }
  size_t totalSize = size8 + ALLOC_HEADER_SIZE;

  //get freelist index number 
  int ilist = (size8/8)-1;
  if (ilist >= N_LISTS - 1) {
    ilist = N_LISTS - 1;
  }

  //iterate over freelists of predetermined size, searching for smallest available block which satisfies request
  header * freelist = &freelistSentinels[ilist];
  bool spotFound = false;
  for (;ilist < (N_LISTS - 1); ilist++) {
    freelist = &freelistSentinels[ilist];
    if (freelist->next != freelist) {
      //if block is available and big enough, we will use it
      size_t compSize = get_size(freelist->next) - ALLOC_HEADER_SIZE;
      if (compSize >= size8) {
        spotFound = true;
        break;
      }
    }
  }
  //obj is the address of the header of the block we will allocate
  header *obj = freelist->next;

  //if we didn't find a big enough block in the ordered freelists, search the last one for a big enough block
  if (!spotFound) {
    freelist = &freelistSentinels[ilist];
    obj = freelist->next;
    while (obj != freelist) {
      size_t compSize = get_size(obj) - ALLOC_HEADER_SIZE;
      if (compSize >= size8) {
        spotFound = true;
        break;
      }
      obj = obj->next;
    }
  }

  //if we still don't have a big enough block, we need to allocate a new chunk from the OS
  if (!spotFound) {
    //TODO: make the coalescing/allocation a function, we may have to do it several times if arena_size < totalSize
    header * newChunk = allocate_chunk(ARENA_SIZE);
    insert_os_chunk(get_header_from_offset(newChunk, -ALLOC_HEADER_SIZE));
    //get right middle fencepost (new chunk's left)
    header * rightFence = get_header_from_offset(newChunk, -ALLOC_HEADER_SIZE);

    //check if new chunk is contigous with old
    bool contig = false;
    if (lastFencePost == get_header_from_offset(rightFence, -ALLOC_HEADER_SIZE)) {
      contig = true;
    }

    if (contig) {
      //get left middle fence (right of penultimate block)
      numOsChunks--;
      header * leftFence = get_header_from_offset(newChunk, -(2 * ALLOC_HEADER_SIZE));

      //coalesce with middle fenceposts
      set_size_and_state(leftFence, (2* ALLOC_HEADER_SIZE) + get_size(newChunk), UNALLOCATED);
      set_state(rightFence, UNALLOCATED);

      //check if can coalesce with last block in penultimate chunk
      header * leftNeighbor = get_left_header(leftFence);
      enum state leftState = get_state(leftNeighbor);
      if (leftState == UNALLOCATED) {
        //take block out of its freelist
        int leftIndex = (get_size(leftNeighbor) - ALLOC_HEADER_SIZE)/8 - 1;
        if (leftIndex < (N_LISTS - 1)) {
          leftNeighbor->next->prev = leftNeighbor->prev;
          leftNeighbor->prev->next = leftNeighbor->next;
        }

        //coalesce last block in penumltimate with new chunk
        set_size(leftNeighbor, get_size(leftNeighbor) + get_size(leftFence));
        obj = leftNeighbor;
      } else {
        obj = leftFence;
        //removing causes a fail
        obj->next = NULL;
        obj->prev = NULL;
      }
    } else {
      obj = newChunk;
    }

    //update right size of last fence post and last fence post
    lastFencePost = get_header_from_offset(obj, get_size(obj));
    lastFencePost->left_size = get_size(obj);

    //make sure we have enough memory
    //adding more blocks to satisfy request (can safely assume they're contiguous)
    while (get_size(obj) < totalSize) {
      header * oldLast = lastFencePost;
      set_state(oldLast, UNALLOCATED);
      oldLast = get_right_header(oldLast);
      set_state(oldLast, UNALLOCATED);
      newChunk = allocate_chunk(ARENA_SIZE);
      insert_os_chunk(newChunk - ALLOC_HEADER_SIZE);
      lastFencePost = get_header_from_offset(newChunk, get_size(newChunk));
      set_size(obj, get_size(obj) + ARENA_SIZE);
      lastFencePost->left_size = get_size(obj);
    }
  }

  //let obj2 be the subsection of our block that is equal to the request size
  //if our block's leftover section is not enough to allocate on its own, allocate it all
  header *obj2 = NULL;
  if (get_size(obj) - totalSize < 32) {
    //allocate obj and take it out of free list
    set_state(obj, ALLOCATED);
    obj->next->prev = obj->prev;
    obj->prev->next = obj->next;

    //update right neighbor's left size and return
    header * obj4 = get_right_header(obj);
    obj4->left_size = get_size(obj);
    return (header *) obj->data;
  } else {
    obj2 = get_header_from_offset(obj, get_size(obj) - totalSize);
  }

  //fill up header for obj2
  set_size_and_state(obj2, totalSize, ALLOCATED);
  obj2->left_size = get_size(obj) - totalSize;

  //change size of obj
  set_size(obj, obj2->left_size);
  obj->left_size = get_size(get_left_header(obj));

  //change size of object right of obj2
  header *obj3 = get_right_header(obj2);
  obj3->left_size = totalSize;

  long index = ((get_size(obj)) - ALLOC_HEADER_SIZE)/8 - 1;
  if (index <= 0) {
    printf("Allocation Index Error\n");
    assert(false);
  }
  if (index >= N_LISTS) {
    index = (N_LISTS) - 1;

  }

  //put obj back into proper freelist
  if (obj->next != NULL && obj->prev != NULL) {
    if (index == N_LISTS - 1) {
      return get_header_from_offset(obj2, ALLOC_HEADER_SIZE);
    }
    obj->next->prev = obj->prev;
    obj->prev->next = obj->next;
  }

  header * listHead = &freelistSentinels[index];
  listHead->next->prev = obj;
  obj->prev = listHead;
  obj->next = listHead->next;
  listHead->next = obj;

  return get_header_from_offset(obj2, ALLOC_HEADER_SIZE);
}

static inline header * ptr_to_header(void * p) {
  return (header *)((char *) p - ALLOC_HEADER_SIZE); //sizeof(header));
}

static inline void deallocate_object(void * p) {
  // TODO implement deallocation
  if (p == NULL) {
    return;
  }

  header * obj = ptr_to_header(p);
  if (get_state(obj) == UNALLOCATED) {
    printf("Double Free Detected\n");
    assert(false);
  }
  set_state(obj, UNALLOCATED);
  header * leftNeighbor = get_left_header(obj);
  enum state leftState = get_state(leftNeighbor);
  header * rightNeighbor = get_right_header(obj);
  enum state rightState = get_state(rightNeighbor);

  if (leftState == UNALLOCATED && rightState  == UNALLOCATED) {
    //TODO: coalesce on both sides of new unallocated block
    //removing neighbors from their old free lists


    int leftIndex = (get_size(leftNeighbor) - ALLOC_HEADER_SIZE)/8 - 1;
    if (leftIndex < (N_LISTS - 1)) {
      leftNeighbor->next->prev = leftNeighbor->prev;
      leftNeighbor->prev->next = leftNeighbor->next;
    }

    rightNeighbor->next->prev = rightNeighbor->prev;
    rightNeighbor->prev->next = rightNeighbor->next;
/*
    leftNeighbor->next->prev = leftNeighbor->prev;
    leftNeighbor->prev->next = leftNeighbor->next;
*/
    //coalesce blocks and update values
    size_t totalSize = get_size(leftNeighbor) + get_size(obj) + get_size(rightNeighbor);
    set_size(leftNeighbor, totalSize);
    get_right_header(rightNeighbor)->left_size = totalSize;

    //insert new big block into free list
    if (leftIndex < (N_LISTS - 1)) {
      long index = ((totalSize) - ALLOC_HEADER_SIZE)/8 - 1;
      if (index >= N_LISTS) index = N_LISTS - 1;
      header * listHead = &freelistSentinels[index];
      listHead->next->prev = leftNeighbor;
      leftNeighbor->prev = listHead;
      leftNeighbor->next = listHead->next;
      listHead->next = leftNeighbor;
    }

  } else if (leftState == UNALLOCATED && ((rightState == FENCEPOST) || (rightState == ALLOCATED))) {
    //TODO: coalesce block with leftneighbor
    //remove left neighbor from its current list


    int leftIndex = (get_size(leftNeighbor) - ALLOC_HEADER_SIZE)/8 - 1;
    if (leftIndex < (N_LISTS - 1)) {
      leftNeighbor->next->prev = leftNeighbor->prev;
      leftNeighbor->prev->next = leftNeighbor->next;
    }
/*
    leftNeighbor->next->prev = leftNeighbor->prev;
    leftNeighbor->prev->next = leftNeighbor->next;
*/
    //coalesce blocks and update values
    size_t totalSize = get_size(leftNeighbor) + get_size(obj);
    set_size(leftNeighbor, totalSize);
    rightNeighbor->left_size = totalSize;

    //insert new big block into free list;
    if (leftIndex < (N_LISTS - 1)) {
      long index = ((totalSize) - ALLOC_HEADER_SIZE)/8 - 1;
      if (index >= N_LISTS) index = N_LISTS - 1;
      header * listHead = &freelistSentinels[index];
      listHead->next->prev = leftNeighbor;
      leftNeighbor->prev = listHead;
      leftNeighbor->next = listHead->next;
      listHead->next = leftNeighbor;
    }
  } else if (((leftState == ALLOCATED) || (leftState == FENCEPOST)) && rightState == UNALLOCATED) {
    //TODO: coalesce block with rightNeighbor
    //remove rightNeighbor from its current list
    int rightIndex = (get_size(rightNeighbor) - ALLOC_HEADER_SIZE)/8 - 1;
    if (rightIndex < (N_LISTS - 1)) {
      rightNeighbor->next->prev = rightNeighbor->prev;
      rightNeighbor->prev->next = rightNeighbor->next;
    }

    //coalesce blocks and update values
    size_t totalSize = get_size(obj) + get_size(rightNeighbor);
    set_size_and_state(obj, totalSize, UNALLOCATED);
    get_right_header(rightNeighbor)->left_size = totalSize;

    //insert new big block into free list
    if (rightIndex < (N_LISTS - 1)) {
      long index = ((totalSize) - ALLOC_HEADER_SIZE)/8 - 1;
      if (index >= N_LISTS) index = N_LISTS - 1;
      header * listHead = &freelistSentinels[index];
      listHead->next->prev = obj;
      obj->prev = listHead;
      obj->next = listHead->next;
      listHead->next = obj;
    } else {
      rightNeighbor->next->prev = obj;
      rightNeighbor->prev->next = obj;
      obj->next = rightNeighbor->next;
      obj->prev = rightNeighbor->prev;
    }
  } else if ((leftState == FENCEPOST || leftState == ALLOCATED) && (rightState == ALLOCATED || rightState == FENCEPOST)) {
    //TODO: simply add block to freelist
    //update state
    set_state(obj, UNALLOCATED);

    //insert block into free list
    long index = ((get_size(obj)) - ALLOC_HEADER_SIZE)/8 - 1;
    if (index >= N_LISTS) index = N_LISTS - 1;
    header * listHead = &freelistSentinels[index];
    listHead->next->prev = obj;
    obj->prev = listHead;
    obj->next = listHead->next;
    listHead->next = obj;
  }

  return;
}

static void init() {
  // Initialize mutex for thread safety
  pthread_mutex_init(&mutex, NULL);

  // Allocate the first chunk from the OS
  header * block = allocate_chunk(ARENA_SIZE);

  header * prevFencePost = get_header_from_offset(block, -ALLOC_HEADER_SIZE);
  insert_os_chunk(prevFencePost);

  lastFencePost = get_header_from_offset(block, get_size(block));

  // Set the base pointer to the beginning of the first fencepost in the first
  // chunk from the OS
  base = ((char *) block) - ALLOC_HEADER_SIZE; //sizeof(header);

  // Initialize freelist sentinels
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    freelist->next = freelist;
    freelist->prev = freelist;
  }

  // Insert first chunk into the free list
  header * freelist = &freelistSentinels[N_LISTS - 1];
  freelist->next = block;
  freelist->prev = block;
  block->next = freelist;
  block->prev = freelist;
}
