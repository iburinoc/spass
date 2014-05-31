#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "file_db.h"
#include "builtin.h"
#include "spass_util.h"
#include "database.h"

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

int get(dbfile_t* dbf, int argc, char** argv) {
	AES_KEY k;
	if(argc < 2) {
		usage_add();
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

	puts(pwtext);

	zfree(pwtext, pw->passlen);
	memset(&k, 0, sizeof(AES_KEY));

	return SUCCESS;
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

static void usage_rm() {
	puts("add usage: spass rm <name>");
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

