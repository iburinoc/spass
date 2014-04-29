#ifndef SPASS_SPASSERR_H
#define SPASS_SPASSERR_H

#define SUCCESS    0 /* success! */
#define ALLOC_FAIL 1 /* could not allocate memory */
#define PW_EXISTS  2 /* password already exists under this name */
#define PW_NEXISTS 3 /* password does not exist under this name */
#define DB_FULL    4 /* no more space in the database for new passwords */

#endif
