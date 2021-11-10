#include "encrypt.h"

/* static functions */
static const BYTE v_header_packer(int file_version,int block_size,int key_length){
    PACKER_CHECK(block_size<0||block_size>8192||block_size%2048!=0,"Block size error");
    PACKER_CHECK(key_length!=32||key_length!=64,"Key length not currect");
    BYTE v_block_size=(block_size/2048)-1;
    if (key_length==32)
        return (BYTE)(0b11110000|(v_block_size<<2)|0b00000000);
    return (BYTE)(0b11110000|(v_block_size<<2)|0b00000001);
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

static const BYTE v_salt_packer  (int salt_length_base,int salt_length_mask){
    PACKER_CHECK(salt_length_base>63||salt_length_base<=0,"Salt length invalid");
    int calc=pow(2,salt_length_mask+1);
    PACKER_CHECK(calc==-1,"Salt length mask error.");
    PACKER_CHECK(salt_length_base%calc!=0,"Salt length error.");
    BYTE v_base=salt_length_base/calc;
    return (BYTE)((salt_length_base<<2)|salt_length_base);
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
}

static const BYTE v_mac_packer (int mac_multiplier,int mac_backup,int need_aead){
    if (need_aead==0)   return (BYTE)(0x00);
    PACKER_CHECK(mac_multiplier<=0||mac_multiplier>15||mac_multiplier%16!=0,"Invalid mac length");
    int v_mac=mac_multiplier/16;
    return (BYTE)(v_mac<<4);
}


static const BYTE v_alg_packer   (int algorithm_type,int security_level,int algorithm_index);

void encrypt_init(){
    int result;
    if (config_arguments.in==NULL){
        result=encrypt_user_input();
    }else{
        /* process file */
    }
}

int encrypt_user_input(){
    char    *plain_text_buff=NULL;
    size_t  plain_text_size=0;
    
    if ((plain_text_size=get_inputtext(&plain_text_buff))<=0){
        fprintf(stderr,"No text provided.\n");
        return 1;
    }
    printf("Do you want to use default config?[Y/N] ");
}

