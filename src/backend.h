#ifndef __BACKEND_H
#define __BACKEND_H

#include <sodium.h>

#include <string.h>
#include <stdio.h>

#include "third_part/base64.h"
#include "utils.h"

#define BYTE unsigned char 

#if defined(__linux__)
    #include <fcntl.h>
    #include <unistd.h>

    #include <sys/ioctl.h>
    #include <sys/types.h>
    #include <sys/stat.h>

    #include <linux/random.h>
#endif

/* store globel file informations */
static struct {
    const char      *file_name;
    struct head_t   *file_head;
    off_t           file_size_total;
} file_info_globel;

/** 
 *  file header struct --   6 bytes information (unsigned char) +
 *                          8 byte pointer to salt +
 *                          8 byte pointer to nonce = 22 bytes.
 *  @param v_head:  4 bit file type : 
 *                  2 bit block size : (block size + 1)*2048 bytes
 *                  2 bit backup (not used yet) 
 *  @param v_kdf:   2 bit kdf type : [0b00=argon2i13;0b01=argon2id13;0b10=scrypts208sha256]
 *                  3 bit operation times : (operation times)*2U
 *                  3 bit memory limit : (memory limit)*100000000*2
 *  @param v_salt:  6 bit base number
 *                  2 bit mask. caculte: (base number)*(2**(mask+1))  
 *  @param v_nonce: 1 bit need nonce (0=no,1=yes),if is 0,v_nonce should be 0x00
 *                  1 bit is AEAD (0=no,1=yes),if is 0,v_mac should be 0x00
 *                  6 bit multiplier. length caculate : 8*(multiplier)
 *  @param v_mac:   4 bit multiplier. length caculate : 16*(multiplier)
 *                  4 bit backup (not used yet)
 *  @param v_alg:   1 bit algorithm type (0=block alg,1=stream alg)
 *                  1 bit security level (0=usually safe,1=not safe)
 *                  6 bit algorithm index (see below)
 *  @param ptr_salt: pointer to salt array
 *  @param ptr_nce : pointer to nonce array
 **/
struct head_t {
    BYTE v_head,v_kdf,v_salt,v_nonce,v_mac,v_alg;
    unsigned char *ptr_salt;
    unsigned char *ptr_nce;
};

/** config struct -- store command line configure
 * @param mode [int]        : 1=encrypt,2=decrypt,3=hmac
 * @param key_type [int]    : 1=password,2=not provided(auto geneate),3=key file
 * @param key [const char *]: if @key_type is 2,key should be NULL
 * @param in [const char *] : input file,if NULL then process user input
 * @param out [const char *]: output file,if NULL then ask user
 * @param ascii [int]       : enable ascii armor
 **/
static struct {
    int mode;
    int key_type;
    int ascii;
    const char *key,*in,*out;
} config_arguments;

/* check /dev/random , only check once */
void check_linux_random_backend();

int key_file_process();

#endif