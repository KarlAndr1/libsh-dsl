#include "libshell.h"

void main() {
	#define PARAMS foo bar
	${ echo PARAMS }
}
