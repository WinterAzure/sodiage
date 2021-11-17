#include "utils.h"
#include "global.h"

#include "ctype.h"

size_t readpassword(char **buff){
    struct termios term;
    printf("Input password:");
    if (tcgetattr(fileno(stdin), &term)<0)
        return -1;
    term.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(stdin), 0, &term)<0)
        return -1;
    *buff=sodium_malloc(256*sizeof(char));
    if (*buff==NULL)
        return -1;
    fgets(*buff, 256*sizeof(char), stdin);
    term.c_lflag |= ECHO;
    tcsetattr(fileno(stdin), 0, &term);
    return strlen(*buff);
}

unsigned char *default_kdf(char *password_raw,const unsigned char *salt_buff){
    static unsigned char *password_kdf;
    password_kdf=malloc(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    if (crypto_pwhash(password_kdf,crypto_aead_xchacha20poly1305_IETF_KEYBYTES,
                    password_raw,strlen(password_raw),salt_buff,crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,crypto_pwhash_ALG_DEFAULT)!=0){
                        ERROR("Memory is not enough.\n");
                        return NULL;
    }
    return password_kdf;
}

const char *get_newfile_name(){
    char newname[512+1]={0};
    printf("\nInput file name to save:");
    fgets(newname,512,stdin);
    if (strcmp(newname,"\n")==0){
        printf("No file name provided. add '.encrypted' to original file.\n");
        config_arguments.output_file=malloc(strlen(config_arguments.raw_file)+32);
        strcpy(config_arguments.output_file,config_arguments.raw_file);
        strcat(config_arguments.output_file,".encrypted");
        return config_arguments.output_file;
    }
    strip(newname);
    config_arguments.output_file=malloc(strlen(newname)+1);
    strcpy(config_arguments.output_file,newname);
    return config_arguments.output_file;
}

char *strip(char *raw){
    size_t len=strlen(raw);
    while(iscntrl(raw[len - 1])) --len;
    while(*raw && iscntrl(*raw)){
        ++raw;--len;
    }
    return strndup(raw,len);
}