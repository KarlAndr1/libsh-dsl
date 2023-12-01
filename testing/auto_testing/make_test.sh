#!/usr/bin/env sh

project_src_dir="$(realpath ../../src)"

mkdir "$1"
printf "#\!/usr/bin/env sh\n%s" "$2" > "$1/test.sh"
printf "void main() { \${ %s }; }" "$2" > "$1/test.c"
cp "$project_src_dir/main.c" "$1/in.txt"
