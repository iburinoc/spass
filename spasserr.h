#ifndef SPASS_SPASSERR_H
#define SPASS_SPASSERR_H

#define SUCCESS    0 /* success! */
#define ALLOC_FAIL 1 /* could not allocate memory */
#define PW_EXISTS  2 /* password already exists under this name */
#define PW_NEXISTS 3 /* password does not exist under this name */
#define DB_FULL    4 /* no more space in the database for new passwords */
#define WRITE_ERR  5 /* could not write to file */
#define READ_ERR   6 /* could not read from file */
#define INV_FILE   7 /* file is not valid scrypt format */

#endif
