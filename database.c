#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <libibur/endian.h>

#include "database.h"
#include "password.h"
#include "spasserr.h"

#ifdef SPASS_DATABASE_DEBUG
#include <stdio.h>
#endif

/* initialize a new database */
pwdb_t* init_db() {
	pwdb_t* db;
	if((db = malloc(sizeof(pwdb_t))) == NULL) {
		errno = ENOMEM;
		goto err0;
	}
	
	db->num = 0;
	db->pws = NULL;
	
	/* success! */
	return db;
	
err0:
	/* failed! */
	return NULL;
}

/* deserialize a database from a buffer */
pwdb_t* deserialize_db(uint8_t* buf, size_t len) {
	pwdb_t* db;
	uint32_t index = 0;
	size_t pos = 0;

	if((db = malloc(sizeof(pwdb_t))) == NULL) {
		errno = ENOMEM;
		goto err0;
	}

	db->num = decbe32(buf);

	if((db->pws = malloc(sizeof(passw_t*) * db->num)) == NULL) {
		errno = ENOMEM;
		goto err1;
	}
	memset(db->pws, 0, sizeof(passw_t*) * db->num);
	
	buf += 4;
	pos += 4;
	while(pos < len && index < db->num) {
		db->pws[index] = deserialize_pw(buf);
		if(db->pws[index] == NULL) {
			goto err2;
		}
		
		size_t sspw = serial_size_pw(db->pws[index]);
		buf += sspw;
		pos += sspw;
		index++;
	}
	
	/* buffer was not proper length */
	if(pos != len || index != db->num) {
		errno = EINVAL;
		goto err2;
	}

	/* success! */
	return db;

err2:
	/* error in read passwords, db must be properly freed */
	free_db(db);
	
	/* avoid double free */
	goto err0;
err1:
	/* original allocation succeeded but pws alloc failed, only free db */
	free(db);
err0:
	/* failed! */
	return NULL;
}

/* serializes the database to the buffer.
 * buf must be at least serial_size_db(db)
 */
void serialize_db(pwdb_t* db, uint8_t* buf) {
	encbe32(db->num, buf);
	buf += 4;
	
	uint32_t i = 0;
	for(i = 0; i < db->num; i++) {
		serialize_pw(db->pws[i], buf);
		buf += serial_size_pw(db->pws[i]);
	}
}

/* find the password in the sorted database and return the index
 * if not found, return 2^32-1 and set errno to EINVAL
 * NOTE: 2^32-1 response is not enough to determine a failure
 * as it is a valid index */
uint32_t find_pw(pwdb_t* db, char* name) {
	if(db->num == 0) {
		errno = EINVAL;
		return (uint32_t) (((uint64_t)(1) << 32) - 1);
	}
	uint32_t min = 0;
	uint32_t max = db->num;
	while(1) {
		uint32_t mid = min + (max-min) / 2;
		int cmp = strcmp(name, db->pws[mid]->name);
		if(cmp == 0) {
			return mid;
		} else {
			if(mid == min) {
				errno = EINVAL;
				return (uint32_t) (((uint64_t)(1) << 32) - 1);
			}
			if(cmp < 0) {
				max = mid;
			} else {
				min = mid;
			}
		}
	}
}

/* find where the password should be inserted 
 * behaviour undefined if the password is already
 * in the database */
uint32_t inspos_pw(pwdb_t* db, char* name) {
	if(db->num == 0) {
		return 0;
	}
	if(db->num == 1) {
		if(strcmp(name, db->pws[0]->name) <= 0) {
			return 0;
		} else {
			return 1;
		}
	}
	uint32_t min = 0;
	uint32_t max = db->num;
	while(1) {
		uint32_t mid = min + (max-min) / 2;
		int cmp = strcmp(name, db->pws[mid]->name);
		if(cmp == 0) {
			return mid;
		} else {
			if(mid == min) {
				return mid + (cmp < 0 ? 0 : 1);
			}
			if(cmp < 0) {
				max = mid;
			} else {
				min = mid;
			}
		}
	}
}

static int pw_exists(pwdb_t* db, char* name) {
	errno = 0;
	find_pw(db, name);
	
	/* check if this password already exists in the databse */
	return errno == 0;
}

/* add a password to the database
 * this method takes ownership of the password
 * and will free it when necessary 
 * returns 0 if successful, -1 if not */
int db_add_pw(pwdb_t* db, passw_t* pw) {
	if(pw_exists(db, pw->name)) {
		/* password already exists under this name */
		return PW_EXISTS;
	}
	
	if(db->num > (((uint64_t)(1) << 32) - 2)) {
		/* no space for new password */
		return DB_FULL;
	}
	
	/* index of inserted password */
	uint32_t inspos = inspos_pw(db, pw->name);
	
	/* make the space for the password */
	if((db->pws = realloc(db->pws, (db->num + 1) * sizeof(passw_t*))) == NULL) {
		/* could not allocate memory */
		return ALLOC_FAIL;
	}
	
	memmove(&db->pws[inspos+1], &db->pws[inspos], (db->num - inspos) * sizeof(passw_t*));

	/* success! */
	db->pws[inspos] = pw;
	db->num++;

	if(db->num > 1 && strcmp(db->pws[0]->name, db->pws[1]->name) > 0) {
		printf("Error: First password does not conform");
		abort();
	}
	
	return SUCCESS;
}

/* removes the password with the given name
 * and returns 0
 * or returns -1 if not found */
int db_rem_pw(pwdb_t* db, char* name) {
	if(!pw_exists(db, name)) {
		/* password does not exist under this name */
		return PW_NEXISTS;
	}

	/* index of password */
	uint32_t rmpos = find_pw(db, name);

	/* password being removed */
	passw_t* rmpw = db->pws[rmpos];

	/* move the passwords after the removed one to take its place */
	memmove(&db->pws[rmpos], &db->pws[rmpos + 1], (db->num - rmpos - 1) * sizeof(passw_t*));
	/* database could be empty */
	if((db->pws = realloc(db->pws, (db->num - 1) * sizeof(passw_t*))) == NULL && db->num != 1) {
		/* could not allocate memory */
		/* cannot return immediately as memory has already been moved */
		memmove(&db->pws[rmpos + 1], &db->pws[rmpos], (db->num - rmpos - 1) * sizeof(passw_t*));
		db->pws[rmpos] = rmpw;
		
		/* database has been fixed, return failure */
		return ALLOC_FAIL;
	}

	/* free password being removed as we own it,
	 * password should be copied if someone wants to keep it */
	free_pw(rmpw);
	db->num--;
	
	/* success! */
	return SUCCESS;
}

/* gets the password with the given name 
 * and returns it, or NULL if not found.
 * note: db maintains ownership of the password.
 * do not free. */
passw_t* db_get_pw(pwdb_t* db, char* name) {
	errno = 0;
	uint32_t pos = find_pw(db, name);
	if(errno == EINVAL) {
		return NULL;
	}
	
	return db->pws[pos];
}

/* returns a list of names in the database,
 * caller owns this list, it must free it 
 * however it does not own the names themselves 
 * (ie only free the returned pointer) */
char** db_list_names(pwdb_t* db) {
	char** list = malloc(sizeof(char*) * db->num);
	uint32_t i;
	
	for(i = 0; i < db->num; i++) {
		list[i] = db->pws[i]->name;
	}
	
	return list;
}

/* frees the database as well as any passwords contained */
void free_db(pwdb_t* db) {
	uint32_t i;
	for(i = 0; i < db->num; i++) {
		if(db->pws[i] != NULL) {
			free_pw(db->pws[i]);
		}
	}
	
	/* clear info */
	memset(db->pws, 0, sizeof(passw_t*) * db->num);
	free(db->pws);
	
	memset(db, 0, sizeof(pwdb_t));
	free(db);
}

/* returns the size of this database when serialized */
uint64_t serial_size_db(pwdb_t* db) {
	uint64_t size = sizeof(uint32_t);
	uint32_t i;
	for(i = 0; i < db->num; i++) {
		size += serial_size_pw(db->pws[i]);
	}
	
	return size;
}
