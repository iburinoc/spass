#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

#include <ibcrypt/zfree.h>

#include "file_db.h"
#include "builtin.h"
#include "spass_util.h"
#include "database.h"
#include "generate.h"

static void usage_add() {
	puts("add usage: spass add <name>");
}

int add(dbfile_t* dbf, int argc, char** argv) {
	int rc;
	AES_KEY k;
	if(argc < 2) {
		usage_add();
		return 0;
	}

	char* name = argv[1];

	if(pw_exists(dbf->db, name)) {
		return PW_EXISTS;
	}

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

	puts("Password added");
	return SUCCESS;
}

int chpw(dbfile_t* dbf, int argc, char** argv) {
	char* npassword = spass_getpass("New password", "Confirm password", 1);
	int rc = resalt_dbf_v00(dbf, npassword);
	zfree(npassword, strlen(npassword));
	if(rc == SUCCESS) {
		dbf->modified = 1;
		return SUCCESS;
	} else {
		return rc;
	}
}

static void usage_get() {
	puts("get usage: spass get <name>");
}

int get(dbfile_t* dbf, int argc, char** argv) {
	AES_KEY k;
	if(argc < 2) {
		usage_get();
		return 0;
	}

	char* name = argv[1];

	passw_t* pw = db_get_pw(dbf->db, name);
	if(pw == NULL) {
		return PW_NEXISTS;
	}

	create_key_AES(dbf->paskey, 256, &k);
	char* pwtext = dec_pw(pw, &k);
	if(pwtext == NULL) {
		memset(&k, 0, sizeof(AES_KEY));
		return ALLOC_FAIL;
	}

	printf("%s", pwtext);
	if(isatty(fileno(stdout))) {
		printf("\n");
	}

	zfree(pwtext, pw->passlen);
	memset(&k, 0, sizeof(AES_KEY));

	return SUCCESS;
}

static struct option gen_options[] = {
	{"help", no_argument, 0, 'h'},
	{"charset", required_argument, 0, 'c'},
	{"length", required_argument, 0, 'l'},
	{0, 0, 0, 0}
};

static char* gen_soptions = "hc:l:";

static void usage_gen() {
	puts("usage: spass gen [--charset <cs>] [--length <len>] name");
}

static void help_gen() {
	usage_gen();
	puts("charset: a list of characters to use in generation.  hyphens may be used to represent filling the gap between characters.  ex: 'a-zA-Z0-9!@#$%^&*\\-_'");
	puts("length : the length of the generated password");
}

int gen(dbfile_t* dbf, int argc, char** argv) {
	int c = 0, rc;
	AES_KEY k;
	char* charset = dfltcset;
	size_t len = 40;
	while(c != -1) {
		int option_index;

		c = getopt_long(argc, argv, gen_soptions, gen_options, &option_index);

		switch(c) {
		case -1: // options done
			break;
		case 'h':
			help_gen();
			return 0;
		case 'c':
			charset = optarg;
			break;
		case 'l':
			len = strtoul(optarg, 0, 0);
			if(len == 0 || (len == ULONG_MAX && errno == ERANGE)) {
				errmessage = "Length argument was invalid";
				return INV_ARG;
			}
			break;
		}
	}

	if(optind >= argc) {
		usage_gen();
		return 0;
	}

	char* name = argv[optind];
	if(pw_exists(dbf->db, name)) {
		return PW_EXISTS;
	}

	char* password = malloc(len + 1);
	if(password == NULL) {
		return ALLOC_FAIL;
	}

	rc = generate(password, len, charset);
	if(rc != SUCCESS) {
		goto err0;
	}

	create_key_AES(dbf->paskey, 256, &k);
	passw_t* pw = init_pw(name, password, len, &k);

	rc = db_add_pw(dbf->db, pw);
	if(rc != SUCCESS) {
		goto err1;
	}
	dbf->modified = 1;

	long ent = entropy(charset, len);
	if(isatty(STDOUT_FILENO)) {
		printf("Password generated with %ld bits of entropy:\n", ent);
	}
	printf("%s", password);
	if(isatty(STDOUT_FILENO)) {
		printf("\n");
	}

	zero_key_AES(&k);
	zfree(password, len);

	return SUCCESS;
err1:
	free_pw(pw);
	zero_key_AES(&k);
err0:
	zfree(password, len);
	return rc;
}

int ls(dbfile_t* dbf, int argc, char** argv) {
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

static void usage_rm() {
	puts("rm usage: spass rm <name>");
}

int rm(dbfile_t* dbf, int argc, char** argv) {
	int rc;
	if(argc < 2) {
		usage_rm();
		return 0;
	}

	char* name = argv[1];

	if(!pw_exists(dbf->db, name)) {
		return PW_NEXISTS;
	}

	rc = db_rem_pw(dbf->db, name);
	if(rc != SUCCESS) {
		return rc;
	}

	dbf->modified = 1;

	puts("Password deleted");
	return SUCCESS;
}

