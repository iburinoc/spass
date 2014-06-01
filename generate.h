#ifndef SPASS_GENERATE_H
#define SPASS_GENERATE_H

#define MAX_CHARSET_LEN 95

extern char* const dfltcset;

int expand_charset(char** ecset, char* cset);

/* pw must be a buffer of size at least len + 1 */
int generate(char* pw, size_t len, char* cset);

#endif

