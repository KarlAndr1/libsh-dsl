#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

int main() {
	char *res = $(ls | grep .c);
	printf("Result: %s\n", res);
	
	char *res2 = $(
		echo "Hello";
		ls | grep .c
	);
	
	printf("Result (2): %s\n", res);
	
	assert(strcmp(res, res2) == 0);
	
	free(res);
	free(res2);
	
	return 0;
}
