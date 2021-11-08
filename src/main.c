#include "backend.h"
#include "hmacutil.h"
#include "encrypt.h"
#include "decrypt.h"
#include "version.h"

#include <argp.h>
#include <stdbool.h>

static char doc[] = "sodiage -- encrypt/decrypt tool use libsodium and openssl.";
static char args_doc[] = "[-adefko?]";

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
    argp_parse(&argp, argc, argv, 0, 0, &config_arguments);
    
    if (config_arguments.mode==2){
        hmac_interactive_wizard();
        exit(EXIT_SUCCESS);
    }
}