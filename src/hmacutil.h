#ifndef __HMACUTIL_H
#define __HMACUTIL_H

#include "backend.h"

#include <openssl/hmac.h>

static const EVP_MD *(*evp_init[])(void)={
    EVP_md4,EVP_md5,
    EVP_sha1,EVP_sha224,EVP_sha256,EVP_sha384,EVP_sha512,
    EVP_sha3_224,EVP_sha3_256,EVP_sha3_384,EVP_sha3_512
};

void hmac_interactive_wizard();

void print_detail(BYTE *data,unsigned int *size);

#endif