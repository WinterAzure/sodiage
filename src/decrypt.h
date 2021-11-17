#ifndef __DECRYPT_H
#define __DECRYPT_H

#include "common.h"

void decrypt_init();

int default_decrypt(FILE *in_fp,FILE *out_fp,
        const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

#endif