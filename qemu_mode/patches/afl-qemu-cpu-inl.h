/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.10.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include <sys/shm.h>
#include "../../config.h"
#include<signal.h>
#include <stdio.h>
/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* A snippet patched into tb_find_slow to inform the parent process that
   we have hit a new block that hasn't been translated yet, and to tell
   it to translate within its own context, too (this avoids translation
   overhead in the next forked-off copy). */

#define AFL_QEMU_CPU_SNIPPET1 do { \
    afl_request_tsl(pc, cs_base, flags); \
  } while (0)

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#define AFL_QEMU_CPU_SNIPPET2 do { \
    if(itb->pc == afl_entry_point) { \
      afl_setup(); \
      afl_forkserver(cpu); \
    } \
    afl_maybe_log(itb->pc, itb); \
  } while (0)

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

/* This is equivalent to afl-as.h: */

static unsigned char *afl_area_ptr;
static unsigned char *patch_area_ptr;
static unsigned char		 *cfg_bits;
static unsigned long int	   *shared_var;
static unsigned char  *virgin_bits;
static unsigned char  *branch_bits;
static unsigned char  *cur_patch_bits;
static unsigned char  matching_address_found;
static target_ulong  tpcaddress;

/* Exported variables populated by the code patched into elfload.c: */

abi_ulong afl_entry_point, /* ELF entry point (_start) */
          afl_start_code,  /* .text start pointer      */
          afl_end_code,    /* .text end pointer        */
          start_offset;

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;

/* Instrumentation ratio: */

static unsigned int afl_inst_rms = MAP_SIZE;

/* Function declarations. */

static void afl_setup(void);
static void afl_forkserver(CPUState*);
static inline void afl_maybe_log(abi_ulong, TranslationBlock *);

static void afl_wait_tsl(CPUState*, int);
static void afl_request_tsl(target_ulong, target_ulong, uint64_t);

/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint64_t flags;
};

static void patch_address(uint8_t * addr){
  if(addr == NULL || *addr == (-1)) return;
  if(((*addr) & 0x1 ) == 0)  *addr = (*addr) + 1;
  else *addr = *(addr) - 1;
}

/* Some forward decls: */

TranslationBlock *tb_htable_lookup(CPUState*, target_ulong, target_ulong, uint32_t);
static inline TranslationBlock *tb_find(CPUState*, TranslationBlock*, int);

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Set up SHM region and initialize other stuff. */


static void afl_setup(void) {

  char *id_str = getenv(SHM_ENV_VAR),
       *inst_r = getenv("AFL_INST_RATIO");
  char *patch_id_str = getenv(PATCH_SHM_ENV_VAR);
  char *cfg_id_str = getenv(CFG_SHM_ENV_VAR);
  char *shared_var_str = getenv(SHARED_SHM_ENV_VAR);
  char *virgin_id_str = getenv(VIRGIN_SHM_ENV_VAR);
  char *branch_id_str = getenv(BRANCH_SHM_ENV_VAR);
  char *cur_patch_id_str = getenv(CUR_PATCH_SHM_ENV_VAR);

  int shm_id, patch_shm_id;
  int cfg_shm_id, shared_var_shm_id,virgin_shm_id,branch_shm_id,cur_patch_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;

  }

  if (id_str && patch_id_str && cfg_id_str && shared_var_str && virgin_id_str && branch_id_str && cur_patch_id_str) {

    shm_id = atoi(id_str);
    patch_shm_id = atoi(patch_id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);
    patch_area_ptr = shmat(patch_shm_id, NULL, 0);

    cfg_shm_id = atoi(cfg_id_str);
    shared_var_shm_id = atoi(shared_var_str);
    virgin_shm_id = atoi(virgin_id_str);
    branch_shm_id = atoi(branch_id_str);
    cur_patch_id = atoi(cur_patch_id_str);
    cfg_bits = shmat(cfg_shm_id, NULL, 0);
    shared_var = shmat(shared_var_shm_id, NULL, 0);
    virgin_bits = shmat(virgin_shm_id, NULL, 0);
    branch_bits = shmat(branch_shm_id, NULL, 0);
    cur_patch_bits = shmat(cur_patch_id, NULL, 0);

    if (afl_area_ptr == (void*)-1 || patch_area_ptr==(void*)-1 || 
    cfg_bits == (void*)-1 || shared_var==(void*)-1 || virgin_bits==(void*)-1 || 
    branch_bits==(void*)-1 || cur_patch_bits == (void*)-1 ) exit(1);
    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;


  }
  start_offset = afl_start_code - (afl_start_code & 0xffffff);

  if (getenv("AFL_INST_LIBS")) {

    afl_start_code = 0;
    afl_end_code   = (abi_ulong)-1;

  }

  /* pthread_atfork() seems somewhat broken in util/rcu.c, and I'm
     not entirely sure what is the cause. This disables that
     behaviour, and seems to work alright? */

  rcu_disable_atfork();

}


/* Fork server logic, invoked once we hit _start. */

static void afl_forkserver(CPUState *cpu) {

  static unsigned char tmp[4];

  if (!afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {

    pid_t child_pid;
    int status, t_fd[2];

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    while(shared_var[BUSY] != 0 ); // wait for parent to finish fiddling

    //check if we need to patch
    if( shared_var[PATCH_NOW] == 1  ){
      shared_var[BUSY] = 1;
      //deregister former patches
      int i=0;
      for(i=0;i<shared_var[PREV_PATCHES];i++) {
        //if(shared_var[PREV_PATCH_LIST_START + i] != 0 && shared_var[PREV_PATCH_LIST_START + i] != 1 ) 
        patch_address(shared_var[PREV_PATCH_LIST_START+i]);
      }
      //register current patches
      for(i=0;i<shared_var[CUR_PATCHES];i++) {
        patch_address(shared_var[CUR_PATCH_LIST_START+i]);
      }
      //Mark the patches so we don't get confused
      for(i=0;i<shared_var[CUR_PATCHES];i++) 
            cur_patch_bits[shared_var[CUR_PATCH_REAL_START + i] & 0xfffff] = 1; 
      
      shared_var[BUSY] = 0;
      shared_var[PATCH_NOW] = 0;
    }

    /* Establish a channel with child to grab translation commands. We'll
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      /* Child process. Close descriptors and run free. */
      // FILE *file1;
      // int j=0;
      // for(j=0;j<30;j++){
      //   if ((file1 = open("fuzz_debug2", O_WRONLY | O_CREAT | O_TRUNC, 0600))){
      //     write(file1,virgin_bits,MAP_SIZE);
      //     close(file1);
      //   }
      //   if ((file1 = open("fuzz_debug1", O_WRONLY | O_CREAT | O_TRUNC, 0600))){
      //     write(file1,virgin_bits,MAP_SIZE);
      //     close(file1);
      //   }
      // }
      
      shared_var[LAST_BLOCK] = 0xdada;
      shared_var[EDGE_INDEX] = 0xdada;
      shared_var[DISCOVERY_STATUS] = 0xda;
      
      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      return;

    }

    /* Parent. */

    close(TSL_FD);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(cpu, t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  }

}


/* The equivalent of the tuple logging routine from afl-as.h. */

static inline void afl_maybe_log(abi_ulong cur_loc, TranslationBlock *itb) {

  static __thread abi_ulong prev_loc, exact_prev_loc=0,count=0;
  abi_ulong tmp_pos,cur_loc_now , cur_loc_tmp, hash_id,br_id;
  abi_ulong br_1,br_2;
  abi_ulong  index1;
  static TranslationBlock *prev_itb=NULL;
  int i;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */

  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr || !patch_area_ptr)
    return;

  cur_loc_tmp = cur_loc;
  cur_loc_tmp  = (cur_loc_tmp >> 4) ^ (cur_loc_tmp << 8);
  cur_loc_tmp &= MAP_SIZE - 1;
  if (cur_loc_tmp >= afl_inst_rms) return;
  abi_ulong index = cur_loc_tmp ^ prev_loc;

  if(shared_var[DISCOVERY_STATUS]==0xad && afl_area_ptr[shared_var[EDGE_INDEX]]!=0){
    //Looks like a loop like structure ,and we wouldn't like to patch it right?
    shared_var[DISCOVERY_STATUS] = 0xda;
  }
  
  
  if(patch_area_ptr[index]>0 && exact_prev_loc>0 ) {
    /*Now  it seems the fuzzer solved the patch itself
      We may remove the patch now
    */
   if( patch_area_ptr[index] == ORIG_DIREC && cur_patch_bits[exact_prev_loc & 0xfffff] == 1 )
   {
      shared_var[DISCOVERY_STATUS] = 0xda;
      shared_var[LAST_BLOCK] = exact_prev_loc ; 
      for(i=0;i<shared_var[CUR_PATCHES];i++){
        if((abi_ulong)shared_var[CUR_PATCH_REAL_START + i] == exact_prev_loc){
            
          // set the bits so we will not find us bumping into this patch again
          cur_patch_bits[exact_prev_loc & 0xfffff] = 0;
          kill(shared_var[PARENT_PID],SIGCONT);
          patch_area_ptr[index]  = PATCH_SOLVED;
        }
      }
      exit(0);
   }
    
  }
  if( exact_prev_loc!=0 ){
    cur_loc_now = 0;
    hash_id = exact_prev_loc & 0xffffff;
    

    if( branch_bits[exact_prev_loc & 0xffffff]==1 ){
        br_id = cur_loc & 0xffffff;
        tmp_pos = hash_id & 0xfffff;
  //       FILE *file1;
  // char message[40]={0};
  // sprintf(message, "fuzz_debug%d0x%llx0x%llx0x%llx",count++,cfg_bits[9 * tmp_pos]!= (hash_id & 0xff)
  //                       ,cfg_bits[9 * tmp_pos + 1]!= ((hash_id >>8) & 0xff), cfg_bits[9 * tmp_pos + 2]!= ((hash_id >>16) & 0xff));
  // if ((file1 = open(message, O_WRONLY | O_CREAT | O_TRUNC, 0600))){
  //    close(file1);
  // }
        while( (cfg_bits[9 * tmp_pos]!= (hash_id & 0xff))
                    ||   (cfg_bits[9 * tmp_pos + 1]!= ((hash_id >>8) & 0xff) ) || (cfg_bits[9 * tmp_pos + 2]!= ((hash_id >>16) & 0xff) )
                    ) 
                          tmp_pos=(tmp_pos + 1)%0x100000;
              FILE *file2;
  // if ((file2 = open("fuzz_debug2", O_WRONLY | O_CREAT | O_TRUNC, 0600))){
  //    close(file2);
  // }
        while( (cfg_bits[9 * tmp_pos] == (hash_id & 0xff))
                    &&   (cfg_bits[9 * tmp_pos + 1]  == ((hash_id >>8) & 0xff)) &&   (cfg_bits[9 * tmp_pos + 2]  == ((hash_id >>16) & 0xff))
                    ) {
          br_1 = cfg_bits[9 * tmp_pos +3] | (cfg_bits[9 * tmp_pos +4] << 8) | (cfg_bits[9 * tmp_pos +5] << 16);
          br_2 = cfg_bits[9 * tmp_pos +6] | (cfg_bits[9 * tmp_pos +7] << 8) | (cfg_bits[9 * tmp_pos +8] << 16);
          if(br_id == br_1) {
            cur_loc_now = br_2;
            break;
          }
          else if(br_id == br_2) {
            cur_loc_now = br_1;
            break;
          }
          else {
            cur_loc_now = 0;
            tmp_pos=(tmp_pos + 1)%0x100000;
            continue;
          }
        }
  //       FILE *file2;
  // if ((file2 = open("fuzz_debug2", O_WRONLY | O_CREAT | O_TRUNC, 0600))){
  //    close(file2);
  // }
        if(cur_loc_now){
          
          cur_loc_now = cur_loc_now + start_offset;
          cur_loc_now  = (cur_loc_now >> 4) ^ (cur_loc_now << 8);
          cur_loc_now &= MAP_SIZE - 1;
          index1 = cur_loc_now ^ prev_loc;
          if(virgin_bits[ index1] == 0xFF && afl_area_ptr[ index1 ] ==0) {
            if(shared_var[DISCOVERY_STATUS] != 0xad){
              shared_var[LAST_BLOCK] = exact_prev_loc;
              shared_var[EDGE_INDEX] = index1;
              shared_var[DISCOVERY_STATUS] = 0xad;
              shared_var[CUR_EDGE_INDEX] = index;
              shared_var[PATCH_POINT] = prev_itb->cond_jump_addr;
            }
            else shared_var[HAS_MORE_PATCHIBILITY] = 1;
          }
        }
    }
    
  }
  prev_itb = itb;
  exact_prev_loc = cur_loc;

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  cur_loc  = cur_loc_tmp;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  afl_area_ptr[index]++;
  prev_loc = cur_loc >> 1;

}


/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint64_t flags) {

  struct afl_tsl t;

  if (!afl_fork_child) return;

  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}

static int is_address_mapped(void *priv, target_ulong start,
                       target_ulong end, unsigned long prot)
{
    if (start <= tpcaddress && end >= tpcaddress)
        matching_address_found = 1;
    return 0;
}


/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUState *cpu, int fd) {

  struct afl_tsl t;
  TranslationBlock *tb;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;

    tb = tb_htable_lookup(cpu, t.pc, t.cs_base, t.flags);
    matching_address_found = 0;
    tpcaddress = t.pc;
    walk_memory_regions(NULL, is_address_mapped);
    if(!tb && matching_address_found) {
      mmap_lock();
      tb_lock();
      tb_gen_code(cpu, t.pc, t.cs_base, t.flags, 0);
      mmap_unlock();
      tb_unlock();
    }

  }

  close(fd);

}
