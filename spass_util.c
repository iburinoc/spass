#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "spass_util.h"
#include "database.h"
#include "file_db.h"

char* cfgfile = "~/.spass.conf";

struct conf cfg = { 0 };

/* expands any tildes in the file path */
char* expand_tilde(char* path) {
	char* HOME = getenv("HOME");
	const size_t hlen = strlen(HOME);
	const size_t plen = strlen(path);

	if(path[0] != '~') {
		/* nothing to do */
		/* return a new arr */
		char* tmp = malloc(plen + 1);
		if(tmp == NULL) {
			return NULL;
		}
		memcmp(tmp, path, plen+1);
		return tmp;
	}

	char* tmp = malloc(hlen + plen);
	if(tmp == NULL) {
		/* failure :C return null to show that we failed */
		return NULL;
	}

	memcpy(tmp, HOME, hlen);
	memcpy(&tmp[hlen], path+1, plen-1);

	tmp[hlen+plen-1] = '\0';
		
	return tmp;
}

int load_cfg() {
	char* expath = expand_tilde(cfgfile);
	if(expath == NULL) {
		return ALLOC_FAIL;
	}

	FILE* cfile = fopen(expath, "r");
	if(cfile == NULL) {
		free(expath);
		if(errno != ENOENT) {
			return READ_ERR;
		} else {
			return NO_CFG;
		}
	}
	char* in = 0;
	size_t n = 0;
	size_t nread = getline(&in, &n, cfile);

	if(nread < 10 || strncmp("DATABASE=", in, 9) != 0) {
		free(expath);
		fclose(cfile);
		return INV_CFG;
	}

	in[nread-1] = '\0';	

	char* path = expand_tilde(in + 9);
	if(path == NULL) {
		free(expath);
		fclose(cfile);
		/* failed to allocate space */
		return ALLOC_FAIL;
	}
	
	cfg.dbfname = path;

	free(in);
	fclose(cfile);
	free(expath);

	return SUCCESS;
}

int write_cfg() {
	if(cfg.dbfname == 0) {
		return INV_CFG;
	}

	char* expath = expand_tilde(cfgfile);
	FILE* cfile = fopen(expath, "w");
	if(cfile == NULL) {
		free(expath);
		return WRITE_ERR;
	}

	if(fwrite("DATABASE=", 9, 1, cfile) != 1) {
		goto err;
	}

	if(fwrite(cfg.dbfname, strlen(cfg.dbfname), 1, cfile) != 1) {
		goto err;
	}

	if(fwrite("\n", 1, 1, cfile) != 1) {
		goto err;
	}

	free(expath);
	fclose(cfile);

	return SUCCESS;

err:
	fclose(cfile);
	free(expath);

	return WRITE_ERR;
}

/* the cfg must already be set */
int load_database(dbfile_t* dbf, char* password) {
	FILE* dbfile;

	if(dbf == NULL) {
		return 0;
	}

	if((dbfile = fopen(cfg.dbfname, "rb")) == NULL) {
		if(errno == ENOENT) {
			printf("No database file found, creating empty one.");
			return init_dflt_dbf_v00(dbf);
		} else {
			return READ_ERR;
		}
	}

	return read_db_v00(dbfile, dbf, password, strlen(password));
}

char* spass_getpass(const char* prompt, const char* confprompt, int usetty) {
	FILE* in;
	char *pw;
	char *confpw;
	struct termios term, term_old;
	int tty;
	size_t read;

	/* try to open the terminal */
	if(!usetty || ((in = fopen("/dev/tty", "r")) == NULL)) {
		in = stdin;
	}

	/* try to turn off echo */
	if((tty = isatty(fileno(in))) != 0) {
		if(tcgetattr(fileno(in), &term_old)) {
			/* failed */
			goto err0;
		}
		memcpy(&term, &term_old, sizeof(struct termios));
		term.c_lflag = (term.c_lflag & ~ECHO) | ECHONL;
		if(tcsetattr(fileno(in), TCSANOW, &term)) {
			goto err0;
		}
	}

tryagain:
	if(tty) {
		printf("%s: ", prompt);
	}

	pw = 0;
	confpw = 0;

	read = 0;
	if((read = getline(&pw, &read, in)) == -1) {
		free(pw);
		goto err0;
	}
	/* remove the new line */
	pw[read-1] = '\0';

	if(confprompt != NULL) {
		if(tty) {
			printf("%s: ", confprompt);
		}
		
		read = 0;
		if((read = getline(&confpw, &read, in)) == -1) {
			goto err1;
		}
		confpw[read-1] = '\0';

		if(strcmp(pw, confpw) != 0) {
			if(tty) {
				printf("Passwords don't match, please try again\n");
			}
			free(pw);
			free(confpw);
			pw = 0;
			confpw = 0;
			goto tryagain;
		}
	}


	/* reset terminal */
	if(tty) {
		if(tcsetattr(fileno(in), TCSANOW, &term_old)) {
			goto err1;
		}
		fclose(in);
	}

	free(confpw);

	return pw;

err1:
	free(pw);
	free(confpw);
err0:
	if(tty) {
		fclose(in);
	}

	return 0;
}

