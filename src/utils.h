#ifndef __UTILS_H
#define __UTILS_H

#include "common.h"

#include <termios.h>

/** readpassword(char **)
 *  read password from stdin and store it to alloced buff
 *  @param buff : should be null
 **/
size_t readpassword(char **buff);

/** unsigned char *default_kdf(char *)
 *  kdf use libsodium's default settings.
 *  length is for xchacha20poly1305
 **/
unsigned char *default_kdf(char *password_raw,const unsigned char *salt_buff);

/* get new file name. It will modify configment_st */
const char *get_newfile_name();

char *strip(char *raw);

#endif