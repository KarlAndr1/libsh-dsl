#define LIBSHELL_INTERNAL
#include "libshell.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <assert.h>

#ifdef unix
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fcntl.h>
#endif

struct char_buff {
	size_t len, cap;
	char *chars;
};

static bool char_buff_fit(struct char_buff *buff, size_t n) {
	if(buff->cap - buff->len < n) {
		size_t new_cap = (buff->len + n) * 3 / 2;
		char *new_buff = realloc(buff->chars, new_cap);
		if(new_buff == NULL)
			return false;
		
		buff->chars = new_buff;
		buff->cap = new_cap;
		
		return true;
	}
	return true;
}

/*
static bool char_buff_write(struct char_buff *buff, const char *chars, size_t n) {
	bool ok = char_buff_fit(buff, n);
	if(!ok)
		return false;
	
	assert(buff->cap - buff->len >= n);
	memcpy(buff->chars + buff->len, chars, n);
	buff->len += n;
	
	return true;
}
*/

static inline long run_process_unix(const char **command, struct char_buff *output, bool async, int *err) {
	int pipes[2];
	if(output != NULL) {
		int perr = pipe(pipes);
		if(perr) {
			*err = 1;
			return 0;
		}
	}
	
	pid_t id = fork();
	if(id == -1) {
		if(output != NULL) {
			close(pipes[0]);
			close(pipes[1]);
		}
		*err = 1;
		return 0;
	}
	
	if(id != 0) { // Parent
		if(output != NULL) {
			close(pipes[1]); // Close the write end of the pipe
			while(true) {
				bool ok = char_buff_fit(output, 128);
				if(!ok) {
					*err = 1;
					break;
				}
				ssize_t n_read = read(pipes[0], &output->chars[output->len], 128);
				if(n_read == -1) {
					*err = 1;
					break;
				}
				
				if(n_read == 0)
					break;
				
				output->len += n_read;
			}
			close(pipes[0]);
			if(*err)
				return 0;
		}
		
		if(async)
			return id;
		
		int wstatus;
		waitpid(id, &wstatus, 0);
		
		if(WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 255) {
			*err = 3;
			return 0;
		}
		
		return WEXITSTATUS(wstatus);
	} else { // Child
		if(output != NULL) {
			close(pipes[0]); // Close the read end of the pipe
			int derr = dup2(pipes[1], STDOUT_FILENO);
			if(derr < 0) {
				close(pipes[1]);
				warn("Unable to pipe output");
				exit(255);
			}
		}
		
		execvp(command[0], (char *const *) command);
		
		//If unable to exec:
		warn("Unable to run '%s'", command[0]);
		exit(255);
		return -1; // This is never reached
	}
}

// Errors:
//	0 - No error
//	1 - Generic error (check errno)
//	2 - Not supported
//	3 - Unable to exec/run
long run_process(const char **command, struct process_output *capture, bool async, int *err) {
	*err = 0;
	struct char_buff output_buffer;
	struct char_buff *output_buffer_ptr = NULL;
	if(capture != NULL) {
		output_buffer_ptr = &output_buffer;
		output_buffer.len = 0;
		output_buffer.cap = 8;
		output_buffer.chars = malloc(sizeof(char) * output_buffer.cap);
		if(output_buffer.chars == NULL) {
			*err = 1;
			return 0;
		}
	}
	
	#ifdef unix
	
	long res = run_process_unix(command, output_buffer_ptr, async, err);
	if(capture != NULL) {
		if(*err == 0) {
			capture->len = output_buffer.len;
			capture->chars = output_buffer.chars;
		} else {
			free(output_buffer.chars);
		}
	}
	return res;
	
	#else
	
	*err = 2;
	return 0;
	
	#endif
}

bool match_wildcard(const char *str, size_t str_len, const char *wildcard, size_t wildcard_len) {
	#define RECURSION_LIMIT 16 // Max amount of wildcard * characters in a wildcard
	static int rec_counter = 0;
	
	START:
	
	if(wildcard_len == 0) // An empty wildcard matches only an empty string
		return str_len == 0;
	
	char wc = *wildcard;
	
	if(wc == '*') {
		wildcard++;
		wildcard_len--;
		
		rec_counter++;
		if(rec_counter == RECURSION_LIMIT)
			return false;
		
		for(ssize_t i = str_len; i >= 0; i--) {
			bool match = match_wildcard(str + i, str_len - i, wildcard, wildcard_len);
			if(match) {
				rec_counter--;
				return true;
			}
		}
		return false;
	} else {
		if(str_len == 0)
			return false;
		
		if(*wildcard == *str) {
			wildcard++;
			wildcard_len--;
			str++;
			str_len--;
			goto START;
		} else {
			return false;
		}
	}
	
	#undef RECURSION_LIMIT
}

#ifdef unix

const char *step_wildcard_unix(const char *wildcard, size_t wildcard_len, size_t *out_len) {
	static struct {
		DIR *dir;
		const char *dir_path;
		size_t dir_path_len;
		const char *file_wildcard;
		size_t file_wildcard_len;
	} wildcard_state = { NULL, NULL, 0, NULL, 0 };
	static char str_buff[4096];
	
	if(wildcard == NULL) {
		closedir(wildcard_state.dir);
		wildcard_state.dir = NULL;
		return NULL;
	}
	
	if(wildcard_state.dir == NULL) {
		const char *wildcard_dir;
		for(wildcard_dir = wildcard + wildcard_len - 1; wildcard_dir > wildcard; wildcard_dir--) {
			if(*wildcard_dir == '/') {
				wildcard_dir++;
				break;
			}
		}
		assert(wildcard_dir <= wildcard + wildcard_len && wildcard_dir >= wildcard);
		size_t wildcard_dir_len = wildcard_dir - wildcard;
		wildcard_state.file_wildcard = wildcard_dir;
		wildcard_state.file_wildcard_len = (wildcard + wildcard_len) - wildcard_state.file_wildcard;
		
		wildcard_state.dir_path = wildcard;
		wildcard_state.dir_path_len = wildcard_dir_len;
		
		if(wildcard_dir_len + 1 > sizeof(str_buff))
			return NULL;
		
		DIR *d;
		if(wildcard_dir_len > 0) {
			memcpy(str_buff, wildcard, wildcard_dir_len);
			str_buff[wildcard_dir_len] = '\0';
		
			d = opendir(str_buff);
		} else {
			d = opendir("./");
		}
		
		if(d == NULL)
			return NULL;
		
		wildcard_state.dir = d;
	}
	
	struct dirent *entry;
	size_t len;
	while(true) {
		entry = readdir(wildcard_state.dir);
		if(entry == NULL)
			break;
		len = strlen(entry->d_name);
		
		if(entry->d_name[0] == '.') {
			if(entry->d_name[1] == '\0')
				continue;
			if(entry->d_name[1] == '.' && entry->d_name[2] == '\0')
				continue;
		}
		
		if(match_wildcard(entry->d_name, len, wildcard_state.file_wildcard, wildcard_state.file_wildcard_len))
			break;
	}
	
	if(entry == NULL || len + wildcard_state.dir_path_len > sizeof(str_buff)) {
		closedir(wildcard_state.dir);
		wildcard_state.dir = NULL;
		return NULL;
	}
	
	memcpy(&str_buff[wildcard_state.dir_path_len], entry->d_name, len);
	
	*out_len = len + wildcard_state.dir_path_len;
	return str_buff;
}

#endif

const char *step_wildcard(const char *wildcard, size_t wildcard_len, size_t *out_len) {
	#ifdef unix
	return step_wildcard_unix(wildcard, wildcard_len, out_len);
	#else
	return NULL;
	#endif
}

static char *make_cstr(const char *str, size_t len) {
	static char buff[4096];
	if(len + 1 > sizeof(buff))
		return NULL;
	
	memcpy(buff, str, len);
	buff[len] = '\0';
	return buff;
}

bool file_exists(const char *path, ssize_t opt_len) {
	bool exists = false;
	if(opt_len >= 0) {
		path = make_cstr(path, opt_len);
		if(path == NULL)
			return false;
	}
	
	FILE *f = fopen(path, "r");
	exists = f != NULL;
	fclose(f);
	
	return exists;
}

// new process interface

#ifdef unix

typedef struct sh_process {
	const char **command;
	int input_pipe;
	int output_pipe;
	
	int capture_pipe;
	
	bool has_started, unable_to_run;
	
	bool input_pipe_used, output_pipe_used, capture_output;
	
	pid_t pid;
} sh_process;

X16(struct sh_process *libsh_dsl_process)
int libsh_dsl_last_exit_code;
FILE *libsh_dsl_tmp_file;
void const *libsh_dsl_null = NULL;

libsh_error libsh_error_flag = LIBSH_ERR_NONE;

static inline libsh_error set_err(libsh_error err) {
	assert(err != LIBSH_ERR_NONE);
	libsh_error_flag = err;
	return err;
}

struct sh_process *create_process(const char **command) {
	struct sh_process *p = malloc(sizeof(struct sh_process));
	if(p == NULL) {
		set_err(LIBSH_ERR_SYSTEM);
		return NULL;
	}
	
	p->command = command;
	p->has_started = false;
	p->input_pipe_used = false;
	p->output_pipe_used = false;
	p->capture_output = false;
	p->unable_to_run = false;
	return p;
}

static void close_process_pipes(struct sh_process *p) {
	if(p->input_pipe_used) {
		close(p->input_pipe);
	}
	if(p->output_pipe_used) {
		close(p->output_pipe);
	}
}

void free_process(struct sh_process *p) {
	
	if(!p->has_started) {
		close_process_pipes(p);
	}
	if(p->capture_output)
		close(p->capture_pipe);
	
	free(p);
}

int exec_safe_pipe(int p[2]) {
	int res = pipe(p);
	fcntl(p[0], F_SETFD, FD_CLOEXEC); //set both ends to close on exec
	fcntl(p[1], F_SETFD, FD_CLOEXEC);
	
	return res;
}

libsh_error capture_process(struct sh_process *p) {
	if(p->output_pipe_used)
		return set_err(LIBSH_ERR_DUPLICATE_ACTION);
	
	int pfd[2];
	int err = exec_safe_pipe(pfd);
	if(err)
		return set_err(LIBSH_ERR_SYSTEM);
	
	p->output_pipe = pfd[1];
	p->capture_pipe = pfd[0];
	p->capture_output = true;
	p->output_pipe_used = true;
	return LIBSH_ERR_NONE;
}

libsh_error pipe_processes(struct sh_process *from, struct sh_process *to) {
	if(from == NULL || to == NULL)
		return LIBSH_ERR_NULL_PROCESS;
	
	if(from->output_pipe_used || to->input_pipe_used)
		return set_err(LIBSH_ERR_DUPLICATE_ACTION);
	
	int pipes[2];
	int err = exec_safe_pipe(pipes);
	if(err)
		return set_err(LIBSH_ERR_SYSTEM);
	
	from->output_pipe = pipes[1];
	to->input_pipe = pipes[0];
	
	from->output_pipe_used = true;
	to->input_pipe_used = true;
	return LIBSH_ERR_NONE;
}

libsh_error pipe_process_to_file(struct sh_process *p, FILE *f) {
	if(p == NULL)
		return LIBSH_ERR_NULL_PROCESS;
	
	if(p->output_pipe_used)
		return set_err(LIBSH_ERR_DUPLICATE_ACTION);
	
	fflush(f);
	int fd = fileno(f);
	if(fd == -1)
		return set_err(LIBSH_ERR_SYSTEM);
	fd = dup(fd);
	if(fd == -1)
		return set_err(LIBSH_ERR_SYSTEM);
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	
	p->output_pipe = fd;
	p->output_pipe_used = true;
	
	return LIBSH_ERR_NONE;
}

libsh_error pipe_file_to_process(FILE *f, struct sh_process *p) {
	if(p == NULL)
		return LIBSH_ERR_NULL_PROCESS;	
	
	if(p->input_pipe_used)
		return set_err(LIBSH_ERR_DUPLICATE_ACTION);
	
	int fd = fileno(f);
	if(fd == -1)
		return set_err(LIBSH_ERR_SYSTEM);
	fd = dup(fd);
	if(fd == -1)
		return set_err(LIBSH_ERR_SYSTEM);
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	
	p->input_pipe = fd;
	p->input_pipe_used = true;
	
	return LIBSH_ERR_NONE;
}

libsh_error process_pass_input(struct sh_process *p, const char *str, size_t len) {
	if(p == NULL)
		return LIBSH_ERR_NULL_PROCESS;	
	
	if(p->input_pipe_used)
		return set_err(LIBSH_ERR_DUPLICATE_ACTION);
	
	int pfd[2];
	int err = exec_safe_pipe(pfd);
	if(err)
		return set_err(LIBSH_ERR_SYSTEM);
	
	ssize_t res = write(pfd[1], str, len);
	close(pfd[1]);
	if(res == -1) {
		close(pfd[0]);
		return set_err(LIBSH_ERR_SYSTEM);
	}
	
	p->input_pipe = pfd[0];
	p->input_pipe_used = true;
	//p->pass_str = str;
	//p->pass_str_len = len;
	
	return LIBSH_ERR_NONE;
}

long start_process(struct sh_process *p) {
	if(p == NULL)
		return 0;	
	
	p->has_started = true;
	
	int exec_err_pipe[2]; // https://stackoverflow.com/questions/13710003/execvp-fork-how-to-catch-unsuccessful-executions
	int err = pipe(exec_err_pipe);
	if(err) {
		set_err(LIBSH_ERR_SYSTEM);
		
		close_process_pipes(p);
		//free_process(p);
		close(exec_err_pipe[0]);
		close(exec_err_pipe[1]);
		
		p->unable_to_run = true; // 'unable to run' means that a process can safely be passed to 'wait_for_process' and freed
		// and also that it has closed all of its pipes, so that any processes that it's been piped into won't stay waiting on
		// input
		return 0;
	}
	
	pid_t id = fork();
	
	if(id == -1) {
		close(exec_err_pipe[0]);
		close(exec_err_pipe[1]);
		
		set_err(LIBSH_ERR_SYSTEM);
		
		close_process_pipes(p);
		//free_process(p);
		
		p->unable_to_run = true;
		return 0;
	}
	
	if(id != 0) { // Parent
		close_process_pipes(p); // The parent doens't have to keep the process pipe handles around (only the child needs them)
		
		close(exec_err_pipe[1]); // close the write end
		int err;
		ssize_t n_read = read(exec_err_pipe[0], &err, sizeof(int));
		close(exec_err_pipe[0]);
		
		
		if(n_read != 0) {
			errno = err;
			set_err(LIBSH_ERR_SYSTEM);
			p->unable_to_run = true;
			return 0;
		}
		p->pid = id;
		
		//printf("Running command %s (%li)\n", p->command[0], id);
		
		return id;
	} else { // Child
		close(exec_err_pipe[0]); // close the read end
		fcntl(exec_err_pipe[1], F_SETFD, FD_CLOEXEC); // set the write end to close on exec
		
		if(p->input_pipe_used) {
			int res = dup2(p->input_pipe, STDIN_FILENO);
			if(res == -1)
				goto CHILD_ERR;
			close(p->input_pipe);
		}
		
		if(p->output_pipe_used) {
			int res = dup2(p->output_pipe, STDOUT_FILENO);
			if(res == -1)
				goto CHILD_ERR;
			close(p->output_pipe);
		}
		
		close_process_pipes(p);
		 // close all fds other than 0, 1, and 2 (stdin, stdout, stderr) https://man7.org/linux/man-pages/man2/close_range.2.html
		// close_range(3, ~0u, CLOSE_RANGE_UNSHARE);
		
		execvp(p->command[0], (char * const*) p->command);
		
		//FALLTHRU in case of error
		CHILD_ERR: 
		{
			int err = errno;
			write(exec_err_pipe[1], &err, sizeof(int));
			_exit(0);
			return 0;
		}
	}
}

libsh_error wait_for_process(struct sh_process *p, int *res) {
	if(p == NULL)
		return LIBSH_ERR_NULL_PROCESS;	
	
	if(!p->has_started) {
		free_process(p);
		return set_err(LIBSH_ERR_PROCESS_NOT_STARTED);
	}
	if(p->unable_to_run) {
		free_process(p);
		return LIBSH_ERR_PROCESS_NOT_STARTED; // does not use set_err, since we don't want to override the error that made
		// the process unable to run
	}
	
	int wstatus;
	waitpid(p->pid, &wstatus, 0);
	free_process(p);
	
	if(res != NULL)
		*res = WEXITSTATUS(wstatus);
	return LIBSH_ERR_NONE;
}

libsh_error wait_and_capture_process(struct sh_process *p, struct process_output *output, int *res) {	
	if(p == NULL) {
		output->chars = NULL;
		output->len = 0;
		return LIBSH_ERR_NULL_PROCESS;
	}
	
	if(!p->has_started) {
		free_process(p);
		output->chars = NULL;
		output->len = 0;
		return set_err(LIBSH_ERR_PROCESS_NOT_STARTED);
	}
	
	if(p->unable_to_run) {
		free_process(p);
		output->chars = NULL;
		output->len = 0;
		return LIBSH_ERR_PROCESS_NOT_STARTED;
	}
	
	if(!p->capture_output) {
		free_process(p);
		output->chars = NULL;
		output->len = 0;
		return set_err(LIBSH_ERR_INVALID_CAPTURE);
	}
	
	size_t len = 0, cap = 0;
	char *buff = NULL;
	
	static char block_buff[256];
	ssize_t n;
	while(( n = read(p->capture_pipe, block_buff, sizeof(block_buff)) ) > 0) {
		if(cap - len < (size_t) n) {
			cap = (cap + n) * 3 / 2;
			char *new_buff = realloc(buff, cap * sizeof(char));
			if(new_buff == NULL)
				goto MEM_ERR;
			
			buff = new_buff;
		}
		
		assert(cap - len >= (size_t) n);
		memcpy(buff + len, block_buff, n);
		len += n;
	}
	
	if(cap - len == 0) {
		cap++;
		char *new_buff = realloc(buff, cap * sizeof(char));
		if(new_buff == NULL)
			goto MEM_ERR;
		buff = new_buff;	
	}
	assert(cap - len >= 1);
	buff[len] = '\0';
	len++;
	
	*output = (struct process_output) { buff, len };
	wait_for_process(p, res);
	return LIBSH_ERR_NONE;
	
	MEM_ERR:
	free(buff);
	*output = (struct process_output) { NULL, 0 };
	wait_for_process(p, res);
	return set_err(LIBSH_ERR_SYSTEM);
}

#else

#warning libsh: Unsupported platform

struct sh_process *create_process(const char **command) {
	set_err(LIBSH_ERR_UNSUPPORTED);
	return NULL;
}

void free_process(struct sh_process *p) {
	
}

libsh_error capture_process(struct sh_process *p) {
	return set_err(LIBSH_ERR_UNSUPPORTED);
}

libsh_error pipe_processes(struct sh_process *from, struct sh_process *to) {
	return set_err(LIBSH_ERR_UNSUPPORTED);
}

libsh_error pipe_process_to_file(struct sh_process *p, FILE *f) {
	return set_err(LIBSH_ERR_UNSUPPORTED);
}

libsh_error pipe_file_to_process(FILE *f, struct sh_process *p) {
	return set_err(LIBSH_ERR_UNSUPPORTED);
}

libsh_error process_pass_input(struct sh_process *p, const char *str, size_t len) {
	return set_err(LIBSH_ERR_UNSUPPORTED);
}

long start_process(struct sh_process *p) {
	return 0;
}

libsh_error wait_for_process(struct sh_process *p, int *res) {
	return set_err(LIBSH_ERR_UNSUPPORTED);
}

libsh_error wait_and_capture_process(struct sh_process *p, struct process_output *output, int *res) {
	return set_err(LIBSH_ERROR_UNSUPPORTED);
}

#endif
