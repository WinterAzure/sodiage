#include "encrypt.h"

/* static functions */
static const BYTE v_header_packer(int file_version,int block_size,int key_length){
    int v_keylen=0;
    if (key_length==32)         v_keylen=0b00000000;
    else if (key_length==64)    v_keylen=0b00000001;
    else{
        error_packer.have_error=1;
        error_packer.message="Invalid Keysize.";
    }
    switch (block_size){
        case 0b00 : return (BYTE)(0b11110000|v_keylen);
        case 1024 : return (BYTE)(0b11110100|v_keylen);
        case 2048 : return (BYTE)(0b11111000|v_keylen);
        case 4096 : return (BYTE)(0b11111100|v_keylen);
        default :   error_packer.have_error=1;
                    error_packer.message="Invalid Blocksize.";
    }
    return 0xff;
}

static const BYTE v_kdf_packer   (int kdf_type,int operation_time,int memory_limit){
    PACKER_CHECK(operation_time<=0||operation_time>14||operation_time%2!=0,"Invalid operation time.");
    PACKER_CHECK(memory_limit<=200000000||memory_limit>1400000000||memory_limit%200000000!=0,"Invalid memory limit.");
    BYTE v_operation_time=operation_time/2;
    BYTE v_memory_limit=memory_limit/100000000/2;
    switch (kdf_type){
        case 0b00 : return (BYTE)(0b00000000|(v_operation_time<<3)|v_memory_limit);break;
        case 0b01 : return (BYTE)(0b01000000|(v_operation_time<<3)|v_memory_limit);break;
        case 0b10 : return (BYTE)(0b10000000|(v_operation_time<<3)|v_memory_limit);break;
        default   : error_packer.have_error=1;
                    error_packer.message="Invalid KDF Algorithm";break;
    }
    return 0xff;
}

static const BYTE v_salt_packer  (int salt_length){
    PACKER_CHECK(salt_length<=0||salt_length>=0xffffffff||salt_length%2!=0,"Invalid salt length.")
    int res = -1; 
    while (salt_length) {
        res++; 
        salt_length=salt_length >> 1;
    } 
    return res; 
}

static const BYTE v_nonce_packer (int need_nonce,int need_aead,int nonce_multiplier){
    PACKER_CHECK(need_nonce==0||need_nonce==1,"Invalid nonce request.");
    if (need_nonce==0x00)   return (BYTE)(0x00);
    PACKER_CHECK(nonce_multiplier<=0||nonce_multiplier>=63||nonce_multiplier%8!=0,"Invalid nonce length");
    int V_nonce_multi=nonce_multiplier/8;
    switch (need_aead){
        case 0x00 : return (BYTE)((0b10000000|0b00000000<<6)|V_nonce_multi);break;
        case 0x01 : return (BYTE)((0b10000000|0b01000000<<6)|V_nonce_multi);break;
        default:    error_packer.have_error=1;
                    error_packer.message="Invalid AEAD request.";break;
    }
    return 0xff;
}

static const BYTE v_mac_packer (int mac_multiplier,int mac_backup,int need_aead){
    if (need_aead==0)   return (BYTE)(0x00);
    PACKER_CHECK(mac_multiplier<=0||mac_multiplier>15||mac_multiplier%16!=0,"Invalid mac length");
    int v_mac=mac_multiplier/16;
    return (BYTE)(v_mac<<4);
}


static const BYTE v_alg_packer   (int algorithm_type,int security_level,int algorithm_index){
    // TODO
    return 0xff;
}

struct head_t *encrypt_filehead_packer(struct head_t *target,unsigned char *ptr_salt,
                                        unsigned char *ptr_nonce,BYTE config_bytes[6]){
    target->v_head=config_bytes[0];
    target->v_kdf=config_bytes[1];
    target->v_salt=config_bytes[2];
    target->v_nonce=config_bytes[3];
    target->v_mac=config_bytes[4];
    target->v_alg=config_bytes[5];
    return target;
}

void encrypt_init(){
    int result;
    if (config_arguments.in==NULL){
        printf("No input file provided,excrypt user input.\n");
        result=encrypt_user_input();
    }else{
        //TODO
    }
}

int encrypt_user_input(){
    char    *plain_text_buff=NULL,*password_buff=NULL;
    size_t  plain_text_size=0,encrypted_text_size=0;
    struct head_t file_head;
    BYTE *target_buff=NULL;
    BYTE *salt_buff,*nonce_buff,*key_buff;
    BYTE config_bytes[6]={0};
    FILE *file_save_fp=NULL;
    
    if ((plain_text_size=get_inputtext(&plain_text_buff))<=0){
        fprintf(stderr,"No text provided.\n");
        return 1;
    }
    if (getpassword("Input password:",&password_buff)!=0){
        fprintf(stderr,"Unable to get password.\n");
        return 1;
    }
    printf("\nDo you want to use default config?[Y/N] ");
    if (getc(stdin)=='Y'){
        /* default config for all */
        CONFIG_CHECK(config_bytes[0]=v_header_packer(0b1111,V_BS_WHOLE,V_KS_32U));
        CONFIG_CHECK(config_bytes[1]=v_kdf_packer(ARGON_2ID13,8,800000000));
        CONFIG_CHECK(config_bytes[2]=v_salt_packer(1024));
        CONFIG_CHECK(config_bytes[3]=v_nonce_packer(1,0,32));
        CONFIG_CHECK(config_bytes[4]=v_mac_packer(0,0,0));
        CONFIG_CHECK(config_bytes[5]=v_alg_packer(1,0,V_ENC_XSalsa20));
        if (encrypt_filehead_packer(&file_head,salt_buff,
                                     nonce_buff,config_bytes)!=0){
            fprintf(stderr,"Unable to generate file header!\n");
            return 1;
        }
        if (encrypt_buff((BYTE *)plain_text_buff,plain_text_size+1,&file_head,&target_buff,key_buff,nonce_buff)!=0){
            fprintf(stderr,"unable to encrypt!\n");
            return 1;
        }
    }else{
        fprintf(stderr,"No user config avilable yet.\n");
        return 1;
    }
    randombytes_buf(salt_buff,1024);
    randombytes_buf(nonce_buff,8*32);
    kdf(password_buff,strlen(password_buff),salt_buff,1024,config_bytes[1],key_buff,crypto_secretbox_KEYBYTES);
    if ((encrypted_text_size=encrypt_buff((BYTE *)plain_text_buff,plain_text_size,
                                            &file_head,&target_buff,key_buff,nonce_buff))==-1){
        fprintf(stderr,"Encrypt failed.\n");
        return 1;
    }
    /* new file fp */
    file_save_fp=fopen(get_new_file_name(),"wb");
    /* write file content */
    if (write_file_header(&file_head,file_save_fp)!=0){
        fprintf(stderr,"Unable to write file.\n");
        return 1;
    }
    if (write_buff(target_buff,encrypted_text_size,file_save_fp)==0){
        fprintf(stderr,"Unable to write to file.\n");
        return 1;
    }
    fflush(file_save_fp);
    fclose(file_save_fp);
    return 0;
}

int encrypt_buff(BYTE *raw,size_t size,const struct head_t *head,BYTE **target_buff,BYTE *key,BYTE *nonce){
    if (raw==NULL||size<=0||head==NULL){
        fprintf(stderr,"Invalid arguments for encrypt buff.\n");
        return -1;
    }
    size_t cipher_text_length=crypto_secretbox_MACBYTES+size;
    *target_buff=malloc(cipher_text_length);
    CHECK_ALLOC(*target_buff);
    crypto_secretbox_easy(*target_buff,raw,size,nonce,key);
    return cipher_text_length;
}