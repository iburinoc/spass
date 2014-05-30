#ifndef SPASS_UTIL_H
#define SPASS_UTIL_H

#include "file_db.h"

struct conf {
	char* dbfname;
};

extern char* cfgfile;

extern struct conf cfg;

/* expands a tilde at the start of the file path to the HOME
 * environment variable
 * value returned if not null should be freed even
 * if a tilde was not expanded */
char* expand_tilde(char* path);

/* load the config from the file and store it in cfg */
int load_cfg();

/* write the config in cfg back to the config file */
int write_cfg();

int load_database(dbfile_t* dbf);

int write_database(dbfile_t* dbf);

char* spass_getpass(const char* prompt, const char* confprompt, int usetty); 

void zfree(void* p, size_t s);

#endif
