// autogenerated by libsh_dsl
#include "libshell.h"
static struct sh_process *libsh_dsl_process_0;
static struct sh_process *libsh_dsl_process_1;
static struct sh_process *libsh_dsl_process_2;
static struct sh_process *libsh_dsl_process_3;
static struct sh_process *libsh_dsl_process_4;
static struct sh_process *libsh_dsl_process_5;
static struct sh_process *libsh_dsl_process_6;
static struct sh_process *libsh_dsl_process_7;
static struct sh_process *libsh_dsl_process_8;
static struct sh_process *libsh_dsl_process_9;
static struct sh_process *libsh_dsl_process_10;
static struct sh_process *libsh_dsl_process_11;
static struct sh_process *libsh_dsl_process_12;
static struct sh_process *libsh_dsl_process_13;
static struct sh_process *libsh_dsl_process_14;
static struct sh_process *libsh_dsl_process_15;
static struct process_output libsh_dsl_capture;
static FILE *libsh_dsl_tmp_file;
static int libsh_dsl_last_exit_code;
//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <err.h>

int main() {
	
	assert(libsh_error_flag == LIBSH_ERR_NONE);
	char *res = (libsh_error_flag = LIBSH_ERR_NONE, libsh_dsl_process_0 = create_process((const char *([])) {"ls", NULL}), libsh_dsl_process_1 = create_process((const char *([])) {"invalid_command", ".c", NULL}), pipe_processes(libsh_dsl_process_0, libsh_dsl_process_1), libsh_dsl_process_2 = create_process((const char *([])) {"cat", NULL}), pipe_processes(libsh_dsl_process_1, libsh_dsl_process_2), capture_process(libsh_dsl_process_2), start_process(libsh_dsl_process_0), start_process(libsh_dsl_process_1), start_process(libsh_dsl_process_2), wait_for_process(libsh_dsl_process_0, &libsh_dsl_last_exit_code), wait_for_process(libsh_dsl_process_1, &libsh_dsl_last_exit_code), wait_and_capture_process(libsh_dsl_process_2, &libsh_dsl_capture, &libsh_dsl_last_exit_code), libsh_error_flag? free(libsh_dsl_capture.chars), NULL : libsh_dsl_capture.chars);
	assert(res == NULL);
	assert(libsh_error_flag == LIBSH_ERR_SYSTEM);
	warn("Error result");
	
	return 0;
}
