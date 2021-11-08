#ifndef __UTILS_H
#define __UTILS_H

#include <termios.h>

#include "backend.h"

#define CHECK_ALLOC(X) if ((X)==NULL){              \
    fprintf(stderr,"Unable to alloc memory!\n");    \
    exit(EXIT_FAILURE);                             \
}

int getpassword(const char *prompt,char *password_save_buff);

size_t get_inputtext(char **message_text);
/*
const char *generate_password_random(int size,char *target){};
const char *generate_password_meaningful(int word_size,char dlm,char *target){};
*/

#endif