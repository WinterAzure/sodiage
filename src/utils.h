#ifndef __UTILS_H
#define __UTILS_H

#include <termios.h>

#include "backend.h"

#define CHECK_ALLOC(X) if ((X)==NULL){              \
    fprintf(stderr,"Unable to alloc memory at %p!\n",X);    \
    exit(EXIT_FAILURE);                             \
}

inline int unsigned_addition_check(unsigned int a,unsigned int b){
    unsigned int c=a+b;
    return c>a;
}

int getpassword(const char *prompt,char *password_save_buff);

size_t get_inputtext(char **message_text);

const char *generate_password_random(int size,char **target);

/** generate_password_meaningful -- get password of english words.
 *  example output: hello-pig-yes-mother-oxygen
 *  @param word_size size of words
 *  @param dlm delimiter such as '-',must be visiable(ascii 33-126)
 *  @param target buff to save the password.
 **/
const char *generate_password_meaningful(int word_size,char dlm,char **target);

void print_as_base64(const char *start,const void *data,size_t data_size,const char *end);

const size_t get_file_size(const char *file_name);

#endif