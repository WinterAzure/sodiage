#include "common.h"
#include "encrypt.h"
#include "decrypt.h"

#include <argp.h>
#include <stdbool.h>

static char doc[] = "sodiage -- simple encrypt/decrypt tool use libsodium.";
static char args_doc[] = "[-ed]";

static struct argp_option options[] = { 
    { "encrypt", 'e', 0,            0, "Encrypt a given file."},
    { "decrypt", 'd', 0,            0, "Decrypt a given file."},
    { "file",    'f', "FILE",       0, "File to operate."},
    { 0 } 
};

static void check_argument_mode(struct argp_state *state){
    if (config_arguments.mode!=0){
        fprintf(stderr,"Invalid usage:Encrypt and Decrypt cannot combine!\n");
        argp_usage(state);
    }
}

static error_t parse_opt (int key,char *arg,struct argp_state *state){
    switch (key){
        case 'e':   check_argument_mode(state);
                    config_arguments.mode=ENCRYPT;break;
        case 'd':   check_argument_mode(state);
                    config_arguments.mode=DECRYPT;break;
        case 'f':   config_arguments.raw_file=arg;break;
        case ARGP_KEY_ARG:
            if (state->arg_num >= 2)
                    ERROR("Too many arguments.");exit(EXIT_FAILURE);
        default:    return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

int main(int argc,char *argv[]){
    if (sodium_init()!=0){
        ERROR("libsodium unable to load.\n");
        exit(EXIT_FAILURE);
    }
    argp_parse(&argp, argc, argv, 0, 0, &config_arguments);
    switch (config_arguments.mode){
        case ENCRYPT: encrypt_init();break;
        case DECRYPT: decrypt_init();break;
    }
    return 0;
}