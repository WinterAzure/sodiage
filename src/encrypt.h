#ifndef __ENCRYPT_H
#define __ENCRYPT_H

#include "backend.h"
#include "utils.h"

#define PACKER_CHECK(X,MSG) if (X){                              \
                                    error_packer.have_error=1;   \
                                    error_packer.message=MSG;    \
                                    return 0xff;                 \
                            }

void encrypt_init();

/**
 * prompt for user input then encrypt it.
 * default config is : block size=0,key length=32,kdf=0b01
 *                     operation time 
 *                     memory limit
 *                     salt length
 *                     nonce length
 *                     algorithm type 1
 **/
int encrypt_user_input();

/* if any packer function found an error,this struct will be modified. */
struct {
    int have_error;
    char *message;
}error_packer;

/* encrypt_fileheader_packer functions */

static const BYTE v_header_packer(int file_version,int block_size,int key_length);
static const BYTE v_kdf_packer   (int kdf_type,int operation_time,int memory_limit);
static const BYTE v_salt_packer  (int salt_length_base,int salt_length_mask);
static const BYTE v_nonce_packer (int need_nonce,int need_aead,int nonce_multiplier);
static const BYTE v_mac_packer   (int mac_multiplier,int mac_backup,int need_aead);
static const BYTE v_alg_packer   (int algorithm_type,int security_level,int algorithm_index);

/**
 * encrypt_filehead_packer -- packer file header
 * @param target : target to save struct head_t,will be set to NULL and then alloc
 * @param ptr_salt @param ptr_nonce : same as their name
 * @param config_bytes : array of 6 bytes.  
 * @return a pointer to allocated struct head_t
 **/
struct head_t *encrypt_filehead_packer(struct head_t *target,unsigned char *ptr_salt,
                                        unsigned char *ptr_nonce,BYTE config_bytes[6]);

#endif