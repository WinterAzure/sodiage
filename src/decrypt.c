#include "common.h"
#include "utils.h"
#include "decrypt.h"

void decrypt_init(){
    /* read salt for kdf */
    FILE *in_fp,*out_fp;
    unsigned char *salt_kdf=malloc(crypto_pwhash_SALTBYTES);
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]={0};
    char *password_buff=NULL;
    
    if ((in_fp=fopen(config_arguments.raw_file,"rb"))==NULL){
        ERROR("Unable to open file.\n");
        exit(EXIT_FAILURE);
    }
    fread(salt_kdf,crypto_pwhash_SALTBYTES,1,in_fp);
    /* get save file location */
    if ((out_fp=fopen(get_newfile_name(),"wb"))==NULL){
        ERROR("Unable to open file for ariting.\n");
        exit(EXIT_FAILURE);
    }
    /* get password and kdf it */
    if (readpassword(&password_buff)==-1){
        ERROR("Invalid password input.\n");
        exit(EXIT_FAILURE);
    }
    unsigned char *key_enc=default_kdf(password_buff,salt_kdf);
    /* decrypt */
    if (default_decrypt(in_fp,out_fp,key)!=0){
        ERROR("Unable to decrypt.\n");
        exit(EXIT_FAILURE);
    }
}

int default_decrypt(FILE *in_fp,FILE *out_fp,
        const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]){
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = -1;
    unsigned char  tag;

    fread(header, 1, sizeof(header), in_fp);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        ERROR("Incomplete head!\nAbort.\n");
        return 1;
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, in_fp);
        eof = feof(in_fp);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
                                                       buf_in, rlen, NULL, 0) != 0) {
            ERROR("corrupted chunk\n");
            return 1;
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && ! eof) {
            ERROR("premature end\n");
            return 1;
        }
        fwrite(buf_out, 1, (size_t) out_len, out_fp);
    } while (! eof);
    return 0;
}