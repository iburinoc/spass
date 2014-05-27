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

static int create_config() {
	char* expath = expand_tilde(cfgfile);
	char* dbfile = 0;
	printf("Creating config file in %s\n", expath);
	printf("Input location for database: ");
	
	size_t read = 0;
	read = getline(&dbfile, &read, stdin);

	if(read == -1) {
		goto err; 
	}

	dbfile[read-1] = '\0';

	cfg.dbfname = dbfile;

	free(expath);

	if(write_cfg() != SUCCESS) {
		goto err;
	}

	return SUCCESS;

err:
	free(expath);
	free(dbfile);

	return IO_ERR;
}

static int writedbf(dbfile_t* dbf, char* password) {
	/* can't rewrite with same nonce */
	dbf->nonce++;

	if(dbf->nonce == 0) {
		resalt_dbf_v00(dbf, password);
	}

	FILE* out;
	if((out = fopen(cfg.dbfname, "wb")) == NULL) {
		return WRITE_ERR;
	}

	int rc = write_db_v00(out, dbf);

	fclose(out);
	return rc;
}

int main(int argv, char** argc) {
	if(argv < 2) {
		usage();
		return -1;
	}

	int (*cmd)(dbfile_t*, int, char**) = 0;
	int i, rc;
	dbfile_t dbf;

	for(i = 0; i < sizeof(builtins)/sizeof(*builtins); i++) {
		if(strcmp(argc[1], builtins[i].name) == 0) {
			cmd = builtins[i].fun;
		}
	}

	if(cmd == 0) {
		cmd_unfound();
		return -1;
	}

	rc = load_cfg();
	if(rc != SUCCESS && rc != NO_CFG) {
		goto err;
	}
	if(rc == NO_CFG) {
		rc = create_config();
		if(rc != SUCCESS) {
			goto err;
		}
	}

	char* pw = spass_getpass("Password", "Confirm password", 1);

	if(pw == NULL) {
		return -1;
	}

	/* begin operation */
	load_database(&dbf, pw);	

	(*cmd)(0, argv-1, argc+1);

	if(dbf.modified) {
		rc = writedbf(&dbf, pw);
		if(rc != SUCCESS) {
			goto err;
		}
	}

	clear_dbf_v00(&dbf);

	free(cfg.dbfname);

	memset(pw, 0, strlen(pw));
	free(pw);

	return EXIT_SUCCESS;

err:
	printf("Error: ");
	switch(rc) {
	case ALLOC_FAIL: puts("Could not allocate memory, is the system out of memory?")             ; break;
	case PW_EXISTS:  puts("A password already exists under this name in the database.")          ; break;
	case PW_NEXISTS: puts("No password was found under this name in the database.")              ; break;
	case DB_FULL:    puts("The database is full.")                                               ; break;
	case WRITE_ERR:  puts("Could not write to file.  Is the given address valid?.")              ; break;
	case READ_ERR:   puts("Could not read database/config from file.  Is the listed file valid?"); break;
	case INV_FILE:   puts("Database file was not of the proper format.")                         ; break;
	case NO_CFG:     puts("No config file was found at $HOME/.spass.conf.")                      ; break;
	case INV_CFG:    puts("Invalid config file, fix it or delete it to regenerate.")             ; break; 
	case IO_ERR:     puts("There was an error using stdin/out.")                                 ; break;
	}

	return EXIT_FAILURE;
}

