#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>

#include "file_db.h"
#include "builtin.h"

static struct option add_options[] = {
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static char* add_soptions = "h";

static struct option get_options[] = {
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static char* get_soptions = "h";

static struct option gen_options[] = {
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static char* gen_soptions = "h";

static void usage_add() {
	puts("usage: spass add [<args>] <name>");
}

static void help_add() {
	usage_add();

	const char* const help = "\n'add' puts an existing password in the database";

	puts(help);
}

int add(dbfile_t* dbf, int argc, char** argv) {
	int c;
	while(c != -1) {
		int option_index;
		
		c = getopt_long(argc, argv, add_soptions, add_options, &option_index);
		
		switch(c) {
		case -1: // options done
			break;
		case 'h':
			help_add();
			return 0;
		}
	}

	char* name = argv[optind];
	puts(name);

	return 0;
}

int get(dbfile_t* dbf, int argc, char** argv) {
	return 0;
}

int gen(dbfile_t* dbf, int argc, char** argv) {
	return 0;
}

