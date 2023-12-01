# libsh DSL - sh style process management in C

## libsh

libshell is a small library (currently only for UNIX) that makes it easy to start processes, pipe from one process to another etc.
```
const char *ext = ".c";
struct sh_process *p1 = create_process((const char *([])) { "ls", "-a", NULL });
struct sh_process *p2 = create_process((const char *([])) { "grep", ext, NULL });
pipe_processes(p1, p2);
capture_process(p2);

start_process(p1);
start_process(p2);

wait_for_process(p1); //Waiting also 'frees' the process struct
char *ls_res = wait_and_capture_process(p2);

printf("Dir:\n%s", ls_res);
free(ls_res);
```
Piping files into processes, and piping processes into files is also supported
```
FILE *from = fopen("test.txt", "r");
FILE *to = fopen("sorted.txt", "w");

struct sh_process *p = create_process((const char *([])) { "sort", NULL });
pipe_file_to_process(from, p);
pipe_process_to_file(p, to);

start_process(p);
wait_for_process(p);
```

## libsh DSL

NOTE: Make sure to always include libshell.h and link with the libshell library when using the libsh DSL. The preprocessor does not handle
this automatically in most cases.

libsh DSL is a preprocessor implementing a small DSL (domain specific language), that makes it easier to use the library.
The previous two examples can instead be written as
```
const char *ext = ".c";
char *ls_res = $(ls -a | grep $ext);

printf("Dir:\n%s", ls_res);
free(ls_res);

${
	sort < test.txt > sorted.txt	
}
```
$() runs and captures a process, ${} runs a process and outputs it to stdout.
For file redirection, either a literal path can be used (as in the example, in which case it automatically calls fopen and fclose)
or a variable containing a valid FILE pointer.
```
${cat test.txt}

FILE *f = fopen("test.txt", "r");
${cat $f}
fclose(f);
```

Currently the DSL does not support running processes asynchronously in the background (& in sh/bash), the DLS always inserts calls to process_wait().

### Error handling & exit codes
The error (if any) caused by the most recent $() or ${} block is kept in the libsh_error_flag variable
```
${unkown_process}
assert(libsh_error_flag == LIBSH_ERR_SYSTEM);
warn("Unable to run process");
```

The exit code returned by the most recent process can be accessed via ``$?``
```
${test -f "foo.txt"}
printf("Result: %i\n", $?);
```

## Using
The library can be included like any other library.
The libsh DSL preprocessor/precompiler (libsh-pc) can either be invoked manually on any C source file (if no arguments are given, it reads from stdin and outputs to stdout)
or be used via the libsh-cc shell script. This script automatically runs the libsh DSL preprocessor after the C preprocessor has run
(this enables macros to be used within $() and ${} blocks), and then invokes ``cc`` to compile the preprocessed result to and object file (.o). It also
passes any extra arguments given (compiler flags/options) to the compiler.
Make sure to update the libsh_pc variable in the libsh-cc script, to wherever the libsh-pc binary is kept (or just to libsh-pc if it is kept inside a PATH
directory).
