#include "libshell.h"

int main() {
	${test -f "foo.txt"}
	printf("Result: %i\n", $?);
}
