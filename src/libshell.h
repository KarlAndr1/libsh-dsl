#ifndef LIBSHELL_H_INCLUDED
#define LIBSHELL_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

struct process_output {
	char *chars;
	size_t len;
};

// legacy process interface
long run_process(const char **command, struct process_output *capture, bool async, int *err);

const char *step_wildcard(const char *wildcard, size_t wildcard_len, size_t *out_len);

bool file_exists(const char *path, ssize_t opt_len); //If opt_len < 0 then path is assumed to be a null-terminated string

// new process interface

typedef enum libsh_error {
	LIBSH_ERR_NONE = 0,
	LIBSH_ERR_DUPLICATE_ACTION,
	//LIBSH_ERR_OUT_OF_MEM,
	LIBSH_ERR_UNSUPPORTED,
	LIBSH_ERR_SYSTEM,
	LIBSH_ERR_PROCESS_NOT_STARTED,
	LIBSH_ERR_INVALID_CAPTURE,
	LIBSH_ERR_NULL_PROCESS,
} libsh_error;

struct sh_process *create_process(const char **command);
void free_process(struct sh_process *p); // Frees the handle/struct, doesn't affect the process itself

libsh_error capture_process(struct sh_process *p);
libsh_error pipe_processes(struct sh_process *from, struct sh_process *to);

libsh_error pipe_process_to_file(struct sh_process *p, FILE *f);
libsh_error pipe_file_to_process(FILE *f, struct sh_process *p);

libsh_error process_pass_input(struct sh_process *p, const char *str, size_t len);

long start_process(struct sh_process *p);

libsh_error wait_for_process(struct sh_process *p, int *res); // also frees the process handle
libsh_error wait_and_capture_process(struct sh_process *p, struct process_output *output, int *res); // same here

extern libsh_error libsh_error_flag;

//struct process_output wait_for_captured_process(struct sh_process *p, int *res); // same here

#define X16(x) \
x##_0; x##_1; x##_2; x##_3; x##_4; x##_5; x##_6; x##_7; x##_8; x##_9; x##_10; x##_11; x##_12; x##_13; x##_14; x##_15;

X16(extern struct sh_process *libsh_dsl_process)
extern int libsh_dsl_last_exit_code;
extern FILE *libsh_dsl_tmp_file;
//extern void const *libsh_dsl_null; //this is so that the libsh_dsl can still use null even if it can't use the preprocessor
extern void const *libsh_dsl_null;
//extern struct libsh_dsl_process0;

#ifndef LIBSHELL_INTERNAL
	#undef X16
#endif

#endif
