# Lab 3 Qustions

>  q1: Study the implemenations of semaphores and descriped the calls that are needed in order for a thread to be able to wait for an event in another thread.

### Producer consumer semaphore example
```
    struct semaphore *t1;
    sema_init(t1, 0);
    /*waits for the semaphore to be incremented by another thread*/
    sema_down(t1);
        // critical section
    sema_up(t2); --> tell producer that data was read
```

```
    struct_semaphore *t2;
    sema_init(t2,1);
    sema_down(t2);
        // critical writing
    sema_up(t1);
    /* will unlock the semaphore in sema_down above*/
```

what we essentially wan't to to is to pass a semaphore pointer to the `thread_craete()` function. It's because the
function creates a new thread while the parent process calling `process_execute()` continues to run. We therefore need
to make sure that the `start_process()` code that is called as soon as the newly created thread is running successfully
starts before the parent process (`process_execute`) continues to run and we will do it with semaphores as shown above.
However, we only need one in this case. It is initialized to 0 and then we call `sema_down(sema)` directly after the
`thread_create()` call. The semaphore should be incremented so that the parent process will be able to continue it's
execution by incrementing the semaphore `sema_up(sema)`after the return of `load()` in `start_process()`.


A good idea would be to pass the aux parameter to the `thread_create()` call that is input to the `start_process()`
function as a structure, similarly to what we did int the `intr_frame` case in the syscall implementation. An example
of how we could achieve this would be to insert an "parent" entry in the `struct tid` and make it have a semaphore as a
structure member. We could then make sure that every time `semaphore_init()` is called, it will append that semaphore,
or set it as only semaphore in it's `struct tid`. I will take a look in the Linux kernel book to check how they have
implemented it in the Linux kernel.


