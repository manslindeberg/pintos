#include "vm/frame.h"
#include "vm/sup_page.h"
#include "vm/swap.h"
#include "bitmap.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"

void frame_free_f(struct frame *);
static struct frame_table ft;

/* helper */
static struct frame* find_frame_by_no(unsigned fn) {
  struct list_elem *e;
  for (e=list_begin(&ft.allframes); e!=list_end(&ft.allframes); e=list_next(e)) {
    struct frame *f = list_entry (e, struct frame, elem);
    if(f->kpage == fn) return f;
  }
  return NULL;
}

void frame_table_init(void) {
  ft.count = 0;
  list_init(&ft.allframes);
  lock_init(&ft.mutex);
}

void* frame_map(void* va, enum palloc_flags flags) {
  struct frame* f = NULL;
  void* pa = palloc_get_page(flags);

  lock_acquire(&ft.mutex);
  
  if(!pa) {
    /* no free frames. should evict */

    /* FIFO*/
    struct sup_page *spg;
    struct frame *f;
    struct list_elem *e;
    size_t *count = swap_count();
    int all_frame_size = list_size(&ft.allframes);
    int fifo_index = (*count);

    int i = 0;
    e = list_begin(&ft.allframes);

    while (i < fifo_index)
    {
        e = list_next(e);
        i++;
    }

    f = list_entry(e, struct frame, elem);
    //list_remove(e);

    struct thread *t = f->owner;
    // we need to look-up which thread that uses this frame and update
    // it's value with new swap index and and telling it that it resides in the
    // swap space
    for (e = list_begin(&t->sup_page_table); e != list_end(&t->sup_page_table);
            e = list_next(e)) {
        spg = list_entry(e, struct sup_page, elem);
        
        if (f->upage == spg->page_no) {
            break;
        }
    }
   
    if (spg == NULL) {
        printf(" cannot find page in sup table \n");
    }

    *count = (*count + 1) % all_frame_size;

    /* increments the index from all-frames list that the swap takes frames from */
    spg->location = SWAP;
    uint8_t index = swap_out(PFNO_TO_ADDR(spg->frame_no));
    spg->swap_index = index; 
    //printf(" swapped out page VA %p & PA %p on swap index %d and new VA %p tid %d\n", PFNO_TO_ADDR(f->upage),PFNO_TO_ADDR(f->kpage), spg->swap_index, va, t->tid, spg->location);
    pa = PFNO_TO_ADDR(f->kpage);
    pagedir_clear_page(t->pagedir, PFNO_TO_ADDR(f->upage));
    //palloc_free_page(PFNO_TO_ADDR(f->kpage));
    f->upage = ADDR_TO_PFNO(va);
    f->owner = thread_current();
    //pa = palloc_get_page(flags);
    lock_release(&ft.mutex);

    //printf("\n returning");
    return pa;

  } else {
    f = (struct frame*)malloc(sizeof(struct frame));
    if(f) {
        f->kpage = ADDR_TO_PFNO(pa);
        f->upage = ADDR_TO_PFNO(va);
        f->owner = thread_current();
        list_push_back(&ft.allframes, &f->elem);
        ft.count++;
    }

   //printf(" assigned %p  PA %p tid %d", PFNO_TO_ADDR(f->upage),PFNO_TO_ADDR(f->kpage), thread_current()->tid);
   lock_release(&ft.mutex);
  }

  return pa;
}

void frame_free(void* pa) {
  lock_acquire(&ft.mutex);
  struct frame* f=find_frame_by_no(ADDR_TO_PFNO(pa));
  if(f) { /* frame found */
    palloc_free_page(PFNO_TO_ADDR(f->kpage));
    list_remove(&f->elem);
    free(f);
  }
  lock_release(&ft.mutex);
}

