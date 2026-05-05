---
layout: post
title: "Fuzzing radare2"
date: 2026-05-05
---

# Intro
Radare2 is a widely used open-source reverse engineering framework.  
After reading [tmpout 1/5](https://tmpout.sh/1/5.html) I decided to point AFL++ at it, partly for practice, partly to see what would shake loose.  
What follows is a condensed version of my notes from the campaign. I found three crashes: a NULL deref, a double free, and a heap corruption. But the more interesting problems were in the setup itself, a multicore configuration where AFL++ instances silently stalled because pipe buffers filled up, and an afl-cmin crash that was manifesting because afl-cmin's forkserver handshake doesn't complete the way afl-fuzz does.  
There's also a [github repo](https://github.com/AGhebrea/fuzzing_r2/) with all the setup scripts.  

# Fuzzing setup & Target harness
The fuzzing setup was iterated upon a few times, the [github scripts](https://github.com/AGhebrea/fuzzing_r2/tree/master/workdir/scripts) are in the final form and represent a solid enough choice.  
After reading some of the docs (listed below) I decided to use the **LLVM LTO** instrumentation backend with **CMPLOG** enabled. I also wanted to do persistent mode and multicore fuzzing setup.  

- [https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/INSTALL.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/INSTALL.md  )
- [https://github.com/AFLplusplus/AFLplusplus?tab=readme-ov-file#quick-start-fuzzing-with-afl](https://github.com/AFLplusplus/AFLplusplus?tab=readme-ov-file#quick-start-fuzzing-with-afl)
- [https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md)
- [https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.lto.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.lto.md)
- [https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.laf-intel.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.laf-intel.md)
- [https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md)
- [https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#c-using-multiple-cores](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#c-using-multiple-cores)
- [https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#b-making-the-input-corpus-unique](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#b-making-the-input-corpus-unique)
- [https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#c-selecting-sanitizers](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#c-selecting-sanitizers)
- [https://gamozolabs.github.io/fuzzing/2018/09/16/scaling_afl.html](https://gamozolabs.github.io/fuzzing/2018/09/16/scaling_afl.html)

I took the example from [README.persistent_mode.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md) and added the check for the **--fuzzing_loop** argument. The code works both under afl++ instrumentation and standalone to facilitate debugging.  

## libc shim
The first thing that I tried was naturally naive and got me nowhere. I wanted to modify the target code to accommodate persistent mode. I spent more time than I'd like to admit trying to fixup radare2 file reading logic. I wanted it to read from **__AFL_FUZZ_TESTCASE_BUF** instead of using the libc **_open_**/**_read_** etc. It was much like a whack-a-mole game, one fix revealed another bug. Eventually I figured out that I could just do a libc shim and solve all of my problems by just providing my own **_open_**/**_read_** implementation which would read from **__AFL_FUZZ_TESTCASE_BUF** instead of the input file.  
For example, the _**open**_ function wrapper is pretty simple:  
``` c
#define FILE_DESC_MAGIC_VAL 999
char* target = NULL;
off_t where = 0;
int hooked_fd = 0;
int hooked = 0;
int     (*open_addr)(const char*, int) = NULL;

#ifdef HOOK_FILE_OPERATIONS
/* define the symbols that target was looking for. */
__asm__(".symver hook_open, open@GLIBC_2.2.5");
__asm__(".symver hook_open, open64@GLIBC_2.2.5");
int open(const char* __file, int __oflag, ...) __attribute__((alias("hook_open")));
int open64(const char* __file, int __oflag, ...) __attribute__((alias("hook_open")));
int __libc_open64(const char* __file, int __oflag, ...) __attribute__((alias("hook_open")));
#endif

/* wrapper code */
int hook_open(const char *__file, int __oflag, ...){
    int ret;
    hook_debug_fprintf("hook_open %s\n", __file);
    /* if filename matches the target that needs hooking, 
     return the fake file descriptor and start keeping track of it. */
    if(!strcmp(target, __file)){
        hook_debug_fprintf("hook_open spoof path\n");         
        hooked_fd = FILE_DESC_MAGIC_VAL;
        hooked = 1;
        return hooked_fd;
    }else{
        ret = open_addr(__file, __oflag);
    }
    if(ret == FILE_DESC_MAGIC_VAL){
        assert(0);
    }
    return ret;
}

__attribute__((constructor)) void init_state()
{
    /* store the libc open function offset so that it can be called later when needed */
    open_addr = dlsym(RTLD_NEXT, "open");
}
```
I've repeated the process for all of the functions that I needed to hook. There is some functionality missing, e.g I don't keep track of **_dup_**, **_dup2_**, **_fcntl_** but for radare2 this worked fine.  
Instead of doing the symbol versioning and definition madness, e.g:  
``` c
__asm__(".symver hook_open, open@GLIBC_2.2.5");
__asm__(".symver hook_open, open64@GLIBC_2.2.5");
int open(const char* __file, int __oflag, ...) __attribute__((alias("hook_open")));
int open64(const char* __file, int __oflag, ...) __attribute__((alias("hook_open")));
int __libc_open64(const char* __file, int __oflag, ...) __attribute__((alias("hook_open")));
```
I could've tried to use sed to replace the strings **open@GLIBC_2.2.5**, **open64@GLIBC_2.2.5**, **__libc_open64**, **open64** with **open** in the radare2 binary and libs, for example. This is a thing that I will be trying out next time.  

## Multicore script
The script is inspired from the post [scaling_afl](https://gamozolabs.github.io/fuzzing/2018/09/16/scaling_afl.html)  
The job of the script is to run afl-fuzz on each available core. It sets up the environment, uses numactl to run afl-fuzz and has a configuration mechanism, you essentially call  
``` python
ca.setConfig(CPUConfig(asan=False,  arg="-S", power="coe"),         10)
```
to tell it to run 10 slave cores on **coe** power schedule
The meat of the [script](https://github.com/AGhebrea/fuzzing_r2/blob/master/workdir/scripts/multicore.py) is this:
``` python
  arr = [
      # It's better to prevent than cure. systemd-run is an option to keep memory 
      # leaks in check but honesly it's better to lower AFL_LOOP iterations
      # "systemd-run", "--user", "--scope", "-p", f"MemoryMax={memory_max}G", # f"MemoryHigh={memory_high}G"
      "numactl", f"--physcpubind={cpu_config.cpu}", "--localalloc",
      "afl-fuzz", "-p", cpu_config.power, "-t", "10000", "-i", INPUT_DIR, "-o", OUTPUT_DIR,
      cpu_config.arg, f"fuzzer{cpu_config.cpu}", "--", 
      target, "-AA", "-qq", "-NN", "--fuzzing_loop", f"{mockfile}"]
  sp = subprocess.Popen(args=arr, env=local_env,
      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  sp.wait()
```
It uses numactl to bind execution to a single core, --localalloc means that it will use only RAM attached to that core (The PC that I was using had two CPUs and --localalloc made a difference)  
Then it just calls afl-fuzz with proper configuration and it passes the arguments for radare2.  
It also calls the [rsync.sh](https://github.com/AGhebrea/fuzzing_r2/blob/master/workdir/scripts/aux/rsync.sh) script in a loop in order to save queue progress periodically.  
The power schedule usage is somewhat arbitrary as I just distributed them as I felt like distributing them, based on their descriptions.  

## Write syscall to STDERR/STDOUT was blocking when doing multicore
The first honest issue that I encountered was that after some time CPU usage dropped considerably. To figure out what was happening I did a strace of one afl-fuzz process that was doing nothing.  
``` sh
strace -f -s 1024 -p <PID>
```
And got something like:  
``` c
write(2, <unfinished ...>)
```
Which meant that the program was blocking on writing to **STDERR**.  
A fun trick to jumpstart the afl-fuzz instance again without having to restart everything was to do:  
``` sh
gdb -p <PID> \
  -ex 'p (int)close(2)' \
  -ex 'p (int)open("/dev/null", 0666)' \
  -ex 'detach' \
  -ex 'quit'
```
But it is better to just add some code to the libc shim that will block writes to **STDOUT** and **STDERR**, and the libc shim must also be preloaded by afl-fuzz.  
It was at this point that I had to compile three separate versions of libc, using the **HOOK_FILE_OPERATIONS** and **HOOK_WRITING** macros (see [libc_shim/build.sh](https://github.com/AGhebrea/fuzzing_r2/blob/master/libc_shim/build.sh)). 
- **libc_noprint.so** is loaded only into afl++ to not have the **STDOUT/STDERR** buffer issue. It is built with **HOOK_WRITING** only which means that it blocks file write operations if they are directed to **STDOUT/STDERR**
- **libc.so** has both the file operations mocking and **STDOUT/STDERR** write blocking.
- **libc_print.so** has only the file operations mocking enabled and I've used it for debugging purposes.

## afl-cmin issue.
After I decided to use all of the radare2-testbins files for fuzzing, I wanted to run them under afl-cmin to remove the uninteresting inputs. That ended up being quite a challenge. afl-cmin kept crashing while afl-fuzz, afl-showmap and the instrumented binary running without afl++ were not crashing. I tried a lot of techniques to see where the crash was. dmesg was telling me the location but I also wanted to see some data, to get a better picture.  
I tried to just use gdb to debug it by doing some combination of these:  
``` sh
gdbserver :1234 ./workdir/scripts/multicore.py
# then in gdb
target remote localhost:1234
set detach-on-fork off
set follow-fork-mode child
set follow-exec-mode new
catch exec
catch fork
```
It did not work because I kept losing the segfault somehow. I believe that it is because of how afl++ handles inferior crashes. Anyways, if I spent more time debugging and understanding how afl++ works I might have had more success with this technique.  
I tried to do a rr recording:  
``` sh
rr record ./workdir/scripts/multicore.py
rr ps              
    PID     PPID    EXIT    CMD
    851143  --      1       afl-cmin -t 100000 -i /tmp/testbins -o /tmp/minimized -- /home/kali/workspace/projects/r2/fuzzing_r2/workdir/targets/fuzzing_4_april/radare2 -AA -NN -qq @@
    851163  851143  0       /home/kali/workspace/projects/r2/fuzzing_r2/workdir/targets/fuzzing_4_april/radare2 -AA -NN -qq @@
    851164  851143  -9      /home/kali/workspace/projects/r2/fuzzing_r2/workdir/targets/fuzzing_4_april/radare2 -AA -NN -qq /tmp/minimized/.afl-cmin.test_input
    851165  851164  -11     (forked without exec)
# then
rr replay -p 851164
```
But this suffered from the same issues as the normal gdb debugging technique. I was still missing the actual segfault.  
Then I tried some ways to generate a core dump and the one that worked was when I set these:  
``` sh
# (order matters)
sudo sysctl -w kernel.core_pattern=/tmp/core.%e.%p
sudo sysctl -w fs.suid_dumpable=2
```
and then loading with AFL_PRELOAD [catchsegv.so](https://github.com/AGhebrea/fuzzing_r2/blob/master/catchsegv/catchsegv.c)  
Then I could finally look at a core dump and see what was going on.  
After getting the core dump, I was able to find the root cause. The target was compiled with afl-clang-lto. In the crashing code, __afl_area_ptr which was stored in the .data segment, was dereferenced, yielding __afl_area_initial (the static fallback bitmap). The instrumentation then wrote to __afl_area_initial + 0x14000, which falls outside the bounds of __afl_area_initial and into a different segment entirely, causing the segfault.  
The bug is that __afl_area_initial is a fixed-size static buffer (0x10000 bytes), but LTO instrumentation assigned an edge ID of 0x14000, which exceeds it. This only manifests under afl-cmin because in that context the forkserver handshake does not complete correctly, leaving __afl_area_ptr pointing at the fallback __afl_area_initial instead of the properly sized shared memory region. Under afl-fuzz and afl-showmap, the handshake succeeds, __afl_area_ptr is updated to the real SHM, and the write is in bounds.  
A fix was to compile using afl-clang-fast or, even simpler, to just set the env var AFL_MAP_SIZE to a sufficiently large power of two (e.g 262144).  
The final script: [afl-cmin.sh](https://github.com/AGhebrea/fuzzing_r2/blob/master/workdir/scripts/aux/afl-cmin.sh)  

## Optimizations
Since you cannot optimize what you cannot measure, I was running:
``` sh
perf top
```
while fuzzing was running. I saw that a lot of time was spent in the kernel on functions that were related to filesystem operations.  
E.g:
```
   6.04%  [kernel]                            [k] link_path_walk.part.0.constprop.0
   3.52%  [kernel]                            [k] __d_lookup_rcu
   3.10%  [kernel]                            [k] generic_permission
   2.49%  [kernel]                            [k] step_into
   2.34%  [kernel]                            [k] memset_erms
   1.71%  [kernel]                            [k] strncpy_from_user
   1.49%  [kernel]                            [k] inode_permission
   1.40%  [kernel]                            [k] filename_lookup
   1.34%  [kernel]                            [k] security_inode_permission
   1.11%  [kernel]                            [k] walk_component
   1.07%  [kernel]                            [k] lookup_fast
   0.97%  [kernel]                            [k] kmem_cache_alloc
   0.91%  [kernel]                            [k] entry_SYSRETQ_unsafe_stack
   0.89%  [kernel]                            [k] __do_sys_newfstatat
   0.89%  [kernel]                            [k] __check_heap_object
   0.71%  [kernel]                            [k] kmem_cache_free
   0.68%  [kernel]                            [k] set_root
   0.67%  [kernel]                            [k] __virt_addr_valid
   0.55%  [kernel]                            [k] __entry_text_start
   0.47%  [kernel]                            [k] path_lookupat
```
Getting the full picture ([run.py script](https://github.com/AGhebrea/fuzzing_r2/blob/master/workdir/scripts/run.py)):  
``` sh
strace -f -e trace=openat,newfstatat,fstat,close,readlink radare2 -AA -NN -qq /usr/bin/ls
# or using the run.py script
./workdir/scripts/run.py -c 'strace -e trace=openat,newfstatat,fstat,close,readlink' -i '-AA -nn -qq /usr/bin/ls' -t <TARGET>
```
As an example, by looking for **openat** syscalls only, it tries to open a lot of files:  
``` c
// ...
openat(AT_FDCWD, "r2kv.sdb", O_RDONLY)  = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "r2kv.sdb", O_RDONLY)  = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/format/symclass.sdb", O_RDONLY) = 3
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/format/symclass.sdb", O_RDONLY) = 3
openat(AT_FDCWD, "signals", O_RDONLY)   = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "signals", O_RDONLY)   = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/fcnsign/cc-x86-32.sdb", O_RDONLY) = 4
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/fcnsign/cc-x86-32.sdb", O_RDONLY) = 4
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/syscall/linux-x86-32.sdb", O_RDONLY) = 4
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/syscall/linux-x86-32.sdb", O_RDONLY) = 4
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/opcodes/x86.sdb", O_RDONLY) = 5
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/opcodes/x86.sdb", O_RDONLY) = 5
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/syscall/linux-x86-32.sdb", O_RDONLY) = 6
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/syscall/linux-x86-32.sdb", O_RDONLY) = 6
openat(AT_FDCWD, "/etc/nsswitch.conf", O_RDONLY|O_CLOEXEC) = 6
openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 6
openat(AT_FDCWD, "/home/alex/.local/share/radare2/fortunes", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/fortunes", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 6
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/fcnsign/cc-x86-64.sdb", O_RDONLY) = 6
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/fcnsign/cc-x86-64.sdb", O_RDONLY) = 6
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/syscall/linux-x86-64.sdb", O_RDONLY) = 6
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/syscall/linux-x86-64.sdb", O_RDONLY) = 6
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/syscall/linux-x86-64.sdb", O_RDONLY) = 4
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/syscall/linux-x86-64.sdb", O_RDONLY) = 4
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/opcodes/x86.sdb", O_RDONLY) = 5
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/opcodes/x86.sdb", O_RDONLY) = 5
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/fcnsign/types.sdb", O_RDONLY) = 7
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/fcnsign/types.sdb", O_RDONLY) = 7
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/fcnsign/types-linux.sdb", O_RDONLY) = 7
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/fcnsign/types-linux.sdb", O_RDONLY) = 7
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/fcnsign/types-64.sdb", O_RDONLY) = 7
openat(AT_FDCWD, "/usr/local/share/radare2/6.1.5/fcnsign/types-64.sdb", O_RDONLY) = 7
openat(AT_FDCWD, "/usr/local/lib/radare2/6.1.5", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 7
openat(AT_FDCWD, "/usr/local/lib/radare2/6.1.5/io_shm.so", O_RDONLY|O_CLOEXEC) = 8
openat(AT_FDCWD, "/home/alex/.local/share/radare2/plugins", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 7
openat(AT_FDCWD, "/usr/local/lib/radare2-extras/6.1.5", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/local/lib/radare2-bindings/6.1.5", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/home/alex/.local/share/radare2/plugins", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 7
openat(AT_FDCWD, "/usr/local/lib/radare2/6.1.5", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 7
openat(AT_FDCWD, "/home/alex/.cache/radare2/history", O_RDONLY) = 7
openat(AT_FDCWD, "/usr/bin/ls", O_RDONLY) = 7
openat(AT_FDCWD, "/usr/bin/ls", O_RDONLY) = 8
```
Those are a lot of files to open. When doing a multicore run this means that all cores are waiting for the kernel to look up the same files, over and over again. Most of the [patch file](https://github.com/AGhebrea/fuzzing_r2/blob/master/patches/fs_fuzzing.patch) is related to the removal of the unnecessary filesystem operations. Also the r2 code must be compiled with -DR_LOG_DISABLE and ran with R2_DEBUG_NOLANG=1 env var set. The compilation flag and the env var remove logging function calls and the loading of some plugins, which did not exist on my machine anyways but were still querying the filesystem. Alternatively, if modifying the code isn't easy, the libc shim could be modified to block these using a blacklist, pretty useful. The optimization is worthwhile but I did not properly measure the performance increase, I've observed around 2x increase in exec/sec.  
Essentially to find where the code does the syscalls you can do this in gdb:  
``` sh
catch syscall openat
catch syscall newfstatat
catch syscall fstat
catch syscall close
catch syscall readlink
run
```
Alternatively, you could write a gdbscript to print a stacktrace and continue when it encounters each syscall, then remove duplicate stack traces and analyze how to remove the calls.  
More optimization would look like this:  
- Look at init code and do bare minimum.
- Look at all syscalls and cull the ones that don't matter in the grand scheme of things.
- Look at all memory init/alloc/free and cull ones that don't matter.
I felt like this was a bit more work than it was worth to me and I settled on just having the filesystem patch which was easier to maintain than a more intrusive patch.  

# Crash triage & Analysis
The triage was pretty simple, when I checked the fuzzing campaign and found a crash, I copied it in a separate folder using the [extract_crashes.sh](https://github.com/AGhebrea/fuzzing_r2/blob/master/workdir/scripts/aux/extract_crashes.sh) script and then ran them with [run_crashes.sh](https://github.com/AGhebrea/fuzzing_r2/blob/master/workdir/scripts/aux/run_crashes.sh) using an uninstrumented ASAN build of the unmodified code. If it reported an error or if it crashed, then I would manually analyze it with gdb.  

As an example, once I got a real crash, the aim was to answer these questions:
- Why it crashes ?  
- Exploitable ?  
- Fixed or moved ?  
After having the answers to these it's easier to start thinking of a fix for the bugs.
Mostly I use [rr](https://rr-project.org/) to debug the crashes, it makes it easy to get to the root cause. I've made a convenience script for this, [debcrash.sh](https://github.com/AGhebrea/fuzzing_r2/blob/master/workdir/scripts/debcrash.sh), which uses another convenience script, [rrrr.sh](https://github.com/AGhebrea/scripts/blob/master/src/rrrr.sh). The ability to set watchpoints on memory addresses and then go back to previous read/write/execute makes the process seamless.  

As previously mentioned, at the point of writing the blog post I've only found three crashes, a NULL deref, a double free and one heap corruption, the latter one being the most interesting one. 

One of them was caught by the radare2 project fuzzing setup and it got fixed before I could submit the issue and fix, it was the double free.  
[Commit de90b1345dd68655b7d6cec264718a33b92f0fb8](https://github.com/radareorg/radare2/commit/de90b1345dd68655b7d6cec264718a33b92f0fb8) still has the bug. You can see that at **_libr/bin/format/elf/elf.c:5624_** the code free's both **g_imports_vec** and **phdr_imports_vec**.  
**g_imports_vec** gets assigned in **_libr/bin/format/elf/elf.c:5464_**  
**_Elf64_load_symbols_from_** eventually calls **_Elf64_load_phdr_imports_** which sets **phdr_symbols_vec** and the return value is stored in **g_imports_vec**, which means **g_imports_vec == phdr_symbols_vec**.  
The patch was made in [commit 56310f2afffe83c7b776cb6488bf837a3fa01733](https://github.com/radareorg/radare2/commit/56310f2afffe83c7b776cb6488bf837a3fa01733) and it removed **phdr_symbols_vec** and **phdr_imports_vec**.  
BTW, if you're interested, to get the commits where bugs were introduced and removed I did a combination of these git commands:  
If the fix/bug is straightforward you can use -S flag, pickaxe and it looks for the first time when string "feature_name" changed its number of occurrences.  
``` sh
git log -S "feature_name" --reverse B..A
# e.g:
git log -S "eo->phdr_symbols_vec" --reverse 491f19e30ff..master
  commit 56310f2afffe83c7b776cb6488bf837a3fa01733
  Author: pancake <pancake@nopcode.org>
  Date:   Tue Feb 10 15:56:21 2026 +0100

      Fix UAF in RBin.ELF.fini ##crash
```
There's also git bisect which is a bit more involved but still really useful for less straightforward cases.  


For a more detailed analysis on the other two, you can see:  
- [#25537](https://github.com/radareorg/radare2/issues/25537)  
- [#25886](https://github.com/radareorg/radare2/issues/25886)  

I'll give some context here as well:  


The issue described in [#25886](https://github.com/radareorg/radare2/issues/25886) is a NULL deref in parse_type when a DIE references abbrev code 0

The other issue, [#25537](https://github.com/radareorg/radare2/issues/25537) can corrupt the heap state. Without an additional write primitive to corrupt allocator control structures, the arbitrary free cannot be developed further than DoS against modern glibc (e.g I checked in glibc 2.43).  
[Script to generate an ELF which will corrupt radare2 glibc heap.](https://github.com/AGhebrea/dwarfgen/blob/e434acbe8ca68da981f0d40d0efc5c878eccd228/gendwarf.py)  
radare2 commit to be used: 61fec9306e6d9e68c326a294624eef5dc84732fb  
the free of the arbitrary **mchunks** is triggered in **_libr/anal/dwarf_process.c:750_**  
Essentially you insert fake **mchunks** by adding sequence types to the [array at line 54](https://github.com/AGhebrea/dwarfgen/blob/e434acbe8ca68da981f0d40d0efc5c878eccd228/gendwarf.py#L54)  
During my prototyping I was not able to get past the check at [malloc.c:4435](https://elixir.bootlin.com/glibc/glibc-2.43/source/malloc/malloc.c#L4435) because the chunk address is on another mmapped segment.
The check is:
``` c
if (__glibc_unlikely (contiguous (av)
    && (char *) nextchunk
    >= ((char *) av->top + chunksize(av->top))))
```
And in our case, **nextchunk** points to another memory segment than **av->top**. So the check **(char *) nextchunk >= ((char *) av->top + chunksize(av->top)** will always be true.

# What I would do differently next time:
- Do a shim if possible and leave code modifications out of it.
- Document performance gained/lost after modifications that I did.
- Learn afl++ by actually reading and debugging its code, to see how it functions. For example in the afl-cmin issue it might have been of great help.
- Devise a faster way to determine go/no go, for example a lot of time was wasted by running "fuzzing campaigns" with libc shim versions that had bugs in them, rendering fuzzing useless. I was thinking of setting up a gdb script that debugs the target once, seeing if it arrives at certain code locations and if it processes data correctly.
- Experiment with writing custom harnesses that do not touch certain file bytes. For example, magic bytes.
- Try out the sed trick mentioned previously to replace versioned symbols in the target binary.