#ifndef SPASS_UTIL_H
#define SPASS_UTIL_H

#include "file_db.h"

struct conf {
	char* dbfname;
};

extern char* cfgfile;

extern struct conf cfg;

/* load the config from the file and store it in cfg */
int load_cfg();

/* write the config in cfg back to the config file */
int write_cfg();

dbfile_t* load_database();

char* spass_getpass(const char* prompt, const char* confprompt, int usetty); 

#endif

