#include "backend.h"
#include "hmacutil.h"
#include "encrypt.h"
#include "decrypt.h"
#include "version.h"

#include <argp.h>
#include <stdbool.h>

static char doc[] = "sodiage -- encrypt/decrypt tool use libsodium and openssl.";
static char args_doc[] = "[-edkfaioh]";

static struct argp_option options[] = { 
    { "encrypt", 'e', 0,            0, "Encrypt a given file."},
    { "decrypt", 'd', 0,            0, "Decrypt a given file."},
    { "key",     'k', "Password",   0, "Enter password."},
    { "key-file",'f', "FILE",       0, "Key File Location"},
    { "ascii-armor",'a',0,          0, "Enable ascii output"},
    { "input",   'i', "FILE",       0, "Input file"},
    { "output"  ,'o', "FILE",       0, "Output file location."},
    { "hmac",    'h', 0,            0, "a simple HMAC　ｔool."},
    { 0 } 
};

static void check_argument_key_mode(struct argp_state *state){
    if (config_arguments.key!=NULL){
        fprintf(stderr,"Key and keyfile cannot combine yet!\n");
        argp_usage(state);
    }
}

static void check_argument_mode(struct argp_state *state){
    if (config_arguments.mode!=0){
        fprintf(stderr,"Invalid usage:Encrypt and Decrypt cannot combine!\n");
        argp_usage(state);
    }
}

static error_t parse_opt (int key,char *arg,struct argp_state *state){
    switch (key){
        case 'e':   check_argument_mode(state);
                    config_arguments.mode=1;break;
        case 'd':   check_argument_mode(state);
                    config_arguments.mode=2;break;
        case 'k':   check_argument_key_mode(state);
                    config_arguments.key_type=1;
                    config_arguments.key=arg;break;
        case 'f':   check_argument_key_mode(state);
                    config_arguments.key_type=3;
                    config_arguments.key=arg;break;
        case 'i':   config_arguments.in=arg;break;
        case 'a':   config_arguments.ascii=1;break;
        case 'o':   config_arguments.out=arg;break;
        case 'h':   config_arguments.mode=2;return 0;
        default:    return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

int main(int argc,char *argv[]){
    if (sodium_init()<0){
        fprintf(stderr,"Libsodium couldn't be initialized, it is not safe to use!\n");
        exit(EXIT_FAILURE);
    }
#if defined(__linux__) && defined(RNDGETENTCNT)
    check_linux_random_backend();
#endif

    argp_parse(&argp, argc, argv, 0, 0, &config_arguments);
    
    FILE *target_fp;
    struct head_t *f_head=NULL;
    if (config_arguments.in!=NULL){
        strcpy(file_info_globel.file_name,config_arguments.in);
        file_info_globel.file_size_total=get_file_size(config_arguments.in);
        if ((target_fp=fopen(config_arguments.in,"rb"))==NULL){
            fprintf(stderr,"Unable to open file %s.\n",config_arguments.in);
            exit(EXIT_FAILURE);
        }
        if (config_arguments.mode==2)
            if ((file_info_globel.file_head=read_file_header(target_fp,&f_head))==NULL){
                fprintf(stderr,"Invalid file head.\n");
                exit(EXIT_FAILURE);
            }
        fclose(target_fp);
    }

    switch (config_arguments.mode){
        case 1:encrypt_init();break;
        case 2:hmac_interactive_wizard();break;
        case 3:decrypt_init();break;
        default:fprintf(stderr,"Invalid usage.\n");
                exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}