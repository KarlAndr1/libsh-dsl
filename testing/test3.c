#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

int main() {
	char *res = $(grep .c < test3.c);
	printf("Result: %s\n", res);
	
	return 0;
}
