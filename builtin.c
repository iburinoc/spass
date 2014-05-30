#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "file_db.h"
#include "builtin.h"
#include "spass_util.h"

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
	puts("add usage: spass add [<args>] <name>");
}

static void help_add() {
	usage_add();

	const char* const help = "\n'add' puts an existing password in the database";

	puts(help);
}

int add(dbfile_t* dbf, int argc, char** argv) {
	int c = 0, rc;
	AES_KEY k;
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

	if(optind >= argc) {
		usage_add();
		return 0;
	}

	char* name = argv[optind];
	char* password = spass_getpass("Password to store", NULL, 1);

	if(password == NULL) {
		return IO_ERR;
	}

	create_key_AES(dbf->paskey, 256, &k);
	passw_t* pw = init_pw(name, password, strlen(password), &k);
	if(pw == NULL) {
		return ALLOC_FAIL;
	}

	memset(&k, 0, sizeof(AES_KEY));

	rc = db_add_pw(dbf->db, pw);
	if(rc != SUCCESS) {
		return rc;
	}

	dbf->modified = 1;
	return 0;
}

int get(dbfile_t* dbf, int argc, char** argv) {
	return 0;
}

int gen(dbfile_t* dbf, int argc, char** argv) {
	return 0;
}

int list(dbfile_t* dbf, int argc, char** argv) {
	char** list = db_list_names(dbf->db);
	if(list == NULL) {
		return ALLOC_FAIL;
	}

	int i;
	for(i = 0; i < dbf->db->num; i++) {
		puts(list[i]);
	}

	return SUCCESS;
}

