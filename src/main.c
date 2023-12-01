#include <stdio.h>
#include <err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#define MAX_COMMANDS_PER_STATEMENT 16

static unsigned line_counter = 1;

static char get_next(FILE *in, bool inside_expr) {
	int c = fgetc(in);
	
	if(c == EOF) {
		if(inside_expr)
			errx(1, "Unexpected end of file on %u", line_counter);
		else
			exit(0);
	}
	
	if(c == '\0')
		errx(1, "Source file contains a null character on line %u", line_counter);
	
	if(c == '\n')
		line_counter++;
		
	return c;
}

static bool accept_char(FILE *in, char c) {
	char nc = get_next(in, true);
	if(nc == c)
		return true;
	
	ungetc(nc, in);
	return false;
}

static bool is_whitespace(char c) {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static bool is_valid_in_word(char c) {
	if(is_whitespace(c))
		return false;
	
	switch(c) {
		case ')':
		case '}':
		case ';':
		case '|':
		case '>':
		case '<':
			return false;
		
		default:
			return true;
	}
}

static bool is_valid_var_char(char c) {
	return (
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'A') ||
		(c >= '0' && c <= '9') ||
		c == '_'
	);
}


static bool is_valid_varname(const char *name) {
	if((name[0] >= '0' && name[0] <= '9') || name[0] == '\0')
		return false;
	
	for(const char *cptr = name; *cptr != '\0'; cptr++) {
		char c = *cptr;
		if(!is_valid_var_char(c))
			return false;
	}
	
	return true;
}

static char *get_word(FILE *in, char *buff, size_t cap, size_t *out_len) {
	if(cap == 0)
		errx(2, "Out of memory in word buffer");

	*out_len = 0;
	
	bool until_delim = accept_char(in, '"');
	
	bool prev_was_escape = false;
	while(true) {		
		char c = get_next(in, true);
		if(prev_was_escape) {
			prev_was_escape = false;
			goto ADD_CHAR;
		}
		
		if(until_delim) {
			if(c == '"')
				break;
		} else if(!is_valid_in_word(c)) {
			ungetc(c, in);
			break;
		}
		
		if(c == '\\') {
			prev_was_escape = true;
			continue;
		}
		
		ADD_CHAR:
		if(*out_len == cap - 1)
			errx(2, "Out of memory in word buffer");
		
		buff[*out_len] = c;
		*out_len += 1;
	}
	
	if(*out_len == 0)
		return NULL;
		
	buff[*out_len] = '\0';
	
	if(buff[0] == '$' && !is_valid_varname(buff + 1)) {
		errx(1, "Invalid variable name (%s) on line %u", buff, line_counter);
	}
	
	return buff;
}

static void skip_space(FILE *in) {
	while(true) {
		char c = get_next(in, true);
		if(!is_whitespace(c)) {
			ungetc(c, in);
			break;
		}
	}
}

static void output_escaped_word(FILE *out, const char *term) {
	putc('"', out);
	for(const char *c = term; *c != '\0'; c++) {
		if(*c == '"')
			fputs("\\\"", out);
		else if(*c == '\\')
			fputs("\\\\", out);
		else
			putc(*c, out);
	}
	putc('"', out);
}

static void compile_command(FILE *in, FILE *out, unsigned statement_index) {
	char statement_buff[1024];
	char *buff_p = statement_buff;
	size_t buff_cap = sizeof(statement_buff);
	
	#define TERM_BUFF_CAP 64
	char *(term_buff[TERM_BUFF_CAP]);
	size_t n_terms = 0;
	
	while(true) {
		skip_space(in);
		
		size_t len;
		char *term = get_word(in, buff_p, buff_cap, &len);
		if(term == NULL)
			break;
		
		assert(buff_cap >= len + 1); // len + the null terminator character
		buff_p += len + 1;
		buff_cap -= len + 1;
		
		if(n_terms == TERM_BUFF_CAP)
			errx(2, "Out of memory in term buffer");
		
		term_buff[n_terms] = term;
		n_terms += 1;
	}
	
	if(n_terms == 0)
		errx(1, "Empty statement on line %u", line_counter);
	
	fprintf(out, "libsh_dsl_process_%u = create_process((const char *([])) {", statement_index);
	
	for(size_t i = 0; i < n_terms; i++) {
		if(i != 0)
			fputs(", ", out);
		
		if(term_buff[i][0] == '$') {
			fputs(term_buff[i] + 1, out);
		} else
			output_escaped_word(out, term_buff[i]);
	}
	
	fputs(", libsh_dsl_null})", out);
	
}

static char *expect_word(FILE *in, char *buff, size_t cap, size_t *out_len) {
	char *word = get_word(in, buff, cap, out_len);
	if(word == NULL)
		errx(1, "Expected term on line %u", line_counter);
	return word;
}

static void compile_expr(FILE *in, FILE *out, bool capture) {	
	if(capture)
		putc('(', out);
	else
		putc('{', out);
	
	fputs("libsh_error_flag = LIBSH_ERR_NONE, ", out);
	
	unsigned statement_index = 0;
	
	bool pipe_next = false;
	
	while(true) {
		if(statement_index == MAX_COMMANDS_PER_STATEMENT)
			errx(1, "Command limit per statement (%u) reached on line %u", MAX_COMMANDS_PER_STATEMENT, line_counter);
		compile_command(in, out, statement_index);
		statement_index += 1;
		
		if(pipe_next) {
			pipe_next = false;
			assert(statement_index >= 2);
			fprintf(out, ", pipe_processes(libsh_dsl_process_%u, libsh_dsl_process_%u)", statement_index - 2, statement_index - 1);
		}
		
		skip_space(in);
		char c = get_next(in, true);
		
		if(c == '<') {
			skip_space(in);
			
			char file_path_buff[512];
			size_t len;
			char *word = expect_word(in, file_path_buff, sizeof(file_path_buff), &len);
			
			if(word[0] == '$') {
				fprintf(out, ", pipe_file_to_process(%s, libsh_dsl_process_%u)", word + 1, statement_index - 1);
			} else {
				fputs(", libsh_dsl_tmp_file = fopen(", out);
				output_escaped_word(out, word);
				fprintf(
					out,
					", \"r\"), pipe_file_to_process(libsh_dsl_tmp_file, libsh_dsl_process_%u), fclose(libsh_dsl_tmp_file)",
					statement_index - 1
				);
			}
			
			skip_space(in);
			c = get_next(in, true);
		}
		
		if(c == '>') {
			skip_space(in);
			
			char file_path_buff[512];
			size_t len;
			char *word = expect_word(in, file_path_buff, sizeof(file_path_buff), &len);
			
			if(word[0] == '$') {
				fprintf(out, ", pipe_process_to_file(libsh_dsl_process_%u, %s)", statement_index - 1, word + 1);
			} else {
				fputs(", libsh_dsl_tmp_file = fopen(", out);
				output_escaped_word(out, word);
				fprintf(
					out,
					", \"w\"), pipe_process_to_file(libsh_dsl_process_%u, libsh_dsl_tmp_file), fclose(libsh_dsl_tmp_file)",
					statement_index - 1
				);
			}
			
			skip_space(in);
			c = get_next(in, true);
		}
		
		if(c == ')' || c == '}' || c == ';') {
			if(capture && c == ')') {
				fprintf(out, ", capture_process(libsh_dsl_process_%u)", statement_index - 1); // Capture the last process/command, of the final statement
			}
			
			for(unsigned i = 0; i < statement_index; i++) {
				fprintf(out, ", start_process(libsh_dsl_process_%u)", i);
			}
			
			for(unsigned i = 0; i < statement_index; i++) {
				if(i == statement_index - 1 && capture && c == ')') // Only the final statement is captured
					fprintf(out, ", wait_and_capture_process(libsh_dsl_process_%u, &libsh_dsl_capture, &libsh_dsl_last_exit_code)", i);
				else
					fprintf(out, ", wait_for_process(libsh_dsl_process_%u, &libsh_dsl_last_exit_code)", i);
			}
			statement_index = 0;
			//first = true;
			
			if(c != ';')
				break;
		} else if(c == '|') { 
			pipe_next = true;
		} else
			errx(1, "Expected delimiter (;) on line %u (got %c)", line_counter, c);
		
		fputs(", ", out);
		//first = false;
	}
	
	if(capture) {
		fputs(", libsh_error_flag? free(libsh_dsl_capture.chars), libsh_dsl_null : libsh_dsl_capture.chars)", out);
	} else
		fputs(";}", out);
}

static void print_main_block_end(int exit_code, void *f) {
	(void) exit_code;
	fputs("\n}", f);
	//fputs("return 0;\n}\n", f);
}

static void compile(FILE *in, FILE *out, bool implicit_main, bool auto_include) {

	if(auto_include) {
		fputs("// autogenerated by libsh_dsl\n", out);
		fputs("#include \"libshell.h\"\n#include \"stdlib.h\"\n", out);
	} /*
		for(unsigned i = 0; i < MAX_COMMANDS_PER_STATEMENT; i++) { //TODO: Figure out a way to only create as many as needed
		fprintf(out, "static struct sh_process *libsh_dsl_process_%u;\n", i);
		}
		fputs("static struct process_output libsh_dsl_capture;\n", out);
		fputs("static FILE *libsh_dsl_tmp_file;\n", out);
		fputs("static int libsh_dsl_last_exit_code;\n", out);
		fputs("//\n\n", out);
	}
	*/
	
	
	if(implicit_main) {
		fputs("void main() {\n#line 0\n", out);
		on_exit(print_main_block_end, out);
	}
	
	while(true) {
		char c = get_next(in, false);
		if(c == '$') {
			char c2 = get_next(in, false);
			if(c2 == '(')
				compile_expr(in, out, true);
			else if(c2 == '{')
				compile_expr(in, out, false);
			else if(c2 == '?') {
				fputs("libsh_dsl_last_exit_code", out);
			} else {
				putc(c, out);
				putc(c2, out);
			}
		} else
			putc(c, out);
	}
}

static FILE *req_file(const char *path, const char *mode) {
	FILE *f = fopen(path, mode);
	if(f == NULL)
		err(2, "Unable to open '%s'", path);
	
	return f;
}

static void *req_alloc(size_t n) {
	void *mem = malloc(n);
	if(mem == NULL)
		err(2, "Unable to alloctate required memory");
	
	return mem;
}

static const char *strchrnul(const char *str, char c) {
	const char *cptr = strchr(str, c);
	if(cptr == NULL)
		cptr = str + strlen(str);
	
	return cptr;
}

struct cmd_opts {
	bool implicit_main;
	bool no_autoinclude;
	const char *in_path;
	const char *out_path;
};

static void parse_shortopts(struct cmd_opts *opts, const char *arg) {
	(void) opts, (void) arg;
	
	for(const char *c = arg; *c != '\0'; c++) {
		switch(*c) {
			
			default:
				errx(3, "Unkown command line option -%c", *c);
		}
	}
}

static void parse_longopt(struct cmd_opts *opts, const char *arg) {
	if(strcmp(arg, "implicit-main") == 0) {
		opts->implicit_main = true;
		return;
	}
	
	if(strcmp(arg, "no-autoinclude") == 0) {
		opts->no_autoinclude = true;
		return;
	}
	
	errx(3, "Unkown command line argument --%s", arg);
}

static void parse_cmd_opts(struct cmd_opts *opts, int argc, const char **argv) {
	for(int i = 0; i < argc; i++) {
		const char *arg = argv[i];
		if(arg[0] == '-') {
			if(arg[1] == '-') {
				parse_longopt(opts, arg + 2);
			} else {
				parse_shortopts(opts, arg + 1);
			}
		} else {
			if(opts->in_path == NULL)
				opts->in_path = arg;
			else if(opts->out_path == NULL)
				opts->out_path = arg;
			else
				warnx("Unkown command line argument provided '%s'; ignoring", arg);
		}
	}
}

static void init_cmd_opts(struct cmd_opts *opts) {
	opts->implicit_main = false;
	opts->no_autoinclude = false;
	opts->in_path = NULL;
	opts->out_path = NULL;
}

int main(int argc, const char **argv) {
	(void) argc, (void) argv;
	
	struct cmd_opts opts;
	init_cmd_opts(&opts);
	parse_cmd_opts(&opts, argc - 1, argv + 1);
	
	FILE *in = stdin;
	FILE *out = stdout;
	
	if(opts.in_path != NULL) {
		if(opts.out_path != NULL) {
			in = req_file(opts.in_path, "r");
			out = req_file(opts.out_path, "w");
		} else {
			in = req_file(opts.in_path, "r");
		
			size_t len = strchrnul(opts.in_path, '.') - opts.in_path;
			char *out_filep = req_alloc(len + sizeof(".dsl.c"));
			memcpy(out_filep, opts.in_path, len);
			strcpy(out_filep + len, ".dsl.c");
		
			out = req_file(out_filep, "w");
			free(out_filep);
		}
	}
	
	compile(in, out, opts.implicit_main, !opts.no_autoinclude);
			
	return 0;
}
