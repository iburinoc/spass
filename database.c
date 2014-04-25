#include <stdint.h>
#include <errno.h>

#include <libibur/endian.h>

#include "database.h"
#include "password.h"

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
	len -= 4;
	while(len > 0 && index < db->num) {
		db->pws[index] = deserialize_pw(buf);
		if(db->pws[index] == NULL) {
			goto err2;
		}
		
		size_t sspw = serial_size_pw(db->pws[index]);
		buf += sspw;
		len -= sspw;
		index++;
	}
	
	/* buffer was not proper length */
	if(len != 0 || index != db->num) {
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

void serialize_db(pwdb_t* db, uint8_t* buf) {
	encbe32(db->num, buf);
	buf += 4;
	
	uint32_t i = 0;
	for(i = 0; i < db->num; i++) {
		serialize_pw(db->pws[i], buf);
		buf += serial_size_pw(db->pws[i]);
	}
}

/* add a password to the database
 * this method takes ownership of the password
 * and will free it when necessary 
 * returns 0 if successful, -1 if not */
int db_add_pw(pwdb_t* db, passw_t* pw);

/* removes the password with the given name
 * and returns 0
 * or returns -1 if not found */
int db_rem_pw(pwdb_t* db, char* name);

/* gets the password with the given name 
 * and returns it, or NULL if not found.
 * note: db maintains ownership of the password */
passw_t* db_get(pwdb_t* db, char* name);

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
