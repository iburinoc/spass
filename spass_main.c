#include <stdio.h>
#include <string.h>

#include "builtin.h"
#include "file_db.h"
#include "spass_util.h"

struct cmds {
	int (*fun)(dbfile_t*, int, char**);
	char* name;
	char* desc;
};

static struct cmds builtins[] = {
	{ &add, "add", "add a new password to the database" },
	{ &get, "get", "retrieve a password from the database" },
	{ &gen, "gen", "generate a new random password and insert it in the database" }
};

static void usage() {
	puts("usage: spass <command> [<args>]");
}

static void cmd_unfound() {
	int i;
	puts("command not found, did you mean one of these?");
	for(i = 0; i < sizeof(builtins)/sizeof(*builtins); i++) {
		printf("%s: %s\n", builtins[i].name, builtins[i].desc);
	}
}

int main(int argv, char** argc) {
	if(argv < 2) {
		usage();
		return -1;
	}

	int (*cmd)(dbfile_t*, int, char**) = 0;
	int i;
	for(i = 0; i < sizeof(builtins)/sizeof(*builtins); i++) {
		if(strcmp(argc[1], builtins[i].name) == 0) {
			cmd = builtins[i].fun;
		}
	}

	if(cmd == 0) {
		cmd_unfound();
		return -1;
	}

	load_cfg();
	printf("%s\n", cfg.dbfname);

	char* pw = spass_getpass("Password", "Confirm password", 1);
	printf("%s\n", pw);

	free(pw);

	(*cmd)(0, argv-1, argc+1);
	
	return 0;
}

