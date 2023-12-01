#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <err.h>

int main() {
	
	assert(libsh_error_flag == LIBSH_ERR_NONE);
	char *res = $(ls | invalid_command .c | cat);
	assert(res == NULL);
	assert(libsh_error_flag == LIBSH_ERR_SYSTEM);
	warn("Error result");
	
	return 0;
}
