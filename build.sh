#!/usr/bin/env sh

out_name=libsh-pc

if which tcc > /dev/null; then
	fast_cc=tcc
	echo "Using TCC for fast builds"
else
	fast_cc=cc
fi

cflags="-Wall -Wextra -Wpedantic -o$out_name"

if [ "$1" = "f" -o "$1" = "fast" ]; then
	echo "Fast build"
	$fast_cc -O0 src/*.c $cflags
elif [ "$1" = "d" -o "$1" = "debug" ]; then
	echo "Debug build"
	cc -fsanitize=leak,address,undefined -g -O0 src/*.c $cflags
elif [ "$1" = "c99" ]; then
	echo "C99 Build"
	cc src/*.c -g -DDEBUG -fsanitize=leak,address,undefined -std=c99 $cflags
else
	echo "Release build"
	cc src/*.c -DNDEBUG -O2 $cflags
fi

echo "Done"
