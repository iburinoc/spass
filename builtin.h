#ifndef SPASS_BUILTIN_H
#define SPASS_BUILTIN_H

#include "file_db.h"

int add(dbfile_t* dbf, int argc, char** argv);

int get(dbfile_t* dbf, int argc, char** argv);

int gen(dbfile_t* dbf, int argc, char** argv);

#endif

