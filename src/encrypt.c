#include "common.h"
#include "utils.h"

int encrypt_default(FILE *out_fd,FILE *in_fd,
        const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]){
    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    unsigned char  tag;

    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof(header),out_fd);
    do{
        rlen = fread(buf_in, 1, sizeof buf_in, in_fd);
        eof = feof(in_fd);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
                                                   NULL, 0, tag);
        fwrite(buf_out, 1, (size_t) out_len, out_fd);
    } while (!eof);
    fflush(out_fd);
    return 0;
}


void encrypt_init(){
#ifdef DEBUG
    printf("Encrypt::Init\n");
#endif
    /* get password and kdf it */
    unsigned char salt[crypto_pwhash_SALTBYTES]={0};
    char *password_buff=NULL;
    if (readpassword(&password_buff)==-1){
        ERROR("Invalid password.\n");
        exit(EXIT_FAILURE);
    }
    randombytes_buf(salt,crypto_pwhash_SALTBYTES);
    unsigned char *key_enc=default_kdf(password_buff,salt);
    if (key_enc==NULL){
        ERROR("Unable to kdf key,exit......\n");
        exit(EXIT_FAILURE);
    }
#ifdef DEBUG
    printf("Encrypt::Key Raw:%s\n",password_buff);
    printf("Encrypt::Key:");
    hex_print(key_enc,crypto_secretstream_xchacha20poly1305_KEYBYTES);
    printf("\n");
    printf("Encrypt::Salt:");
    hex_print(salt,crypto_pwhash_SALTBYTES);
    printf("\n");
#endif
    /* get file descriptor */
    FILE *in_fp,*out_fp;
    if ((in_fp=fopen(config_arguments.raw_file,"rb"))==NULL){
        ERROR("Unable to open raw file !\n");
        exit(EXIT_FAILURE);
    }
    if ((out_fp=fopen(get_newfile_name(),"wb"))==NULL){
        ERROR("Unable to open output file for wruting!\n");
        exit(EXIT_FAILURE);
    }
    /* write file head (kdf salt) */
    fwrite(salt,crypto_pwhash_SALTBYTES,1,out_fp);
    fflush(out_fp);
    /* read encrypt */
    if (encrypt_default(out_fp,in_fp,key_enc)!=0){
        ERROR("Unable to encrypt!");
        exit(EXIT_FAILURE);
    }
}


