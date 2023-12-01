#!/usr/bin/env sh

project_src_dir="$(realpath ../../src)"
preprocessor_path="$(realpath ../../libsh-pc)"

verbose=""
if [ "$1" = -v -o "$1" = --verbose ]; then
	verbose="true"
fi

read_res_file() {
	if [ -f result ]; then
		cat result
		rm result
	else
		printf ""
	fi
}

for test in ./*; do
	if ! [ -d "$test" ]; then
		continue
	fi
	
	cd "$test"
	echo "Entering $test"
	
	sh_stdout=$(sh ./test.sh)
	sh_file_res=$(read_res_file)
	failed=""
	
	"$preprocessor_path" < test.c > processed_test.c
	cc processed_test.c "$project_src_dir/libshell.c" "-I$project_src_dir" -g -fsanitize=address,leak,undefined -otest.out
	c_stdout=$(./test.out)
	c_file_res=$(read_res_file)
	
	if [ -n "$verbose" ]; then
		n="
"
		echo "---- c stdout ----$n$c_stdout$n---- sh stdout ----$n$sh_stdout$n----"
		echo "---- c file output ----$n$c_file_res$n---- sh file output ----$n$sh_file_res$n----"
	fi
	
	if [ "$c_stdout" != "$sh_stdout" ]; then
		echo "Stdout different"
		echo "$c_stdout" | cat -n > /tmp/libsh_testing_cmp1 # https://stackoverflow.com/questions/38950802/how-to-display-line-numbers-in-side-by-side-diff-in-unix
		echo "$sh_stdout" | cat -n > /tmp/libsh_testing_cmp2
		failed="true"
	elif [ "$c_file_res" != "$sh_file_res" ]; then
		echo "File output different"
		echo "$c_file_res" | cat -n > /tmp/libsh_testing_cmp1
		echo "$sh_file_res" | cat -n > /tmp/libsh_testing_cmp2
		failed="true"
	fi
	
	if [ -n "$failed" ]; then
		diff --text -C 3 /tmp/libsh_testing_cmp1 /tmp/libsh_testing_cmp2
		echo "Test $test failed"
	else
		echo "Test $test passed"
	fi
	
	cd ../
done
