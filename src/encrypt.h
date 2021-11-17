#ifndef __ENCRYPT_H
#define __ENCRYPT_H

#include "common.h"

void encrypt_init();

/* deafult file encrypt ,from libsodium demo code */
int encrypt_default(FILE *out_fd,FILE *in_fd,
        const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

#endif