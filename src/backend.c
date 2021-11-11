#include "backend.h"

#if defined(__linux__) && defined(RNDGETENTCNT)

void check_linux_random_backend(){
    int fd = open("/dev/random", O_RDONLY);
    int c;
    if (fd==-1){
        fprintf(stderr,"Unable to open /dev/random.\n");
        (void)close(fd);
    }
    if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160) {
        fputs("This system doesn't provide enough entropy to quickly generate high-quality random numbers.\n"
              "The service will not start until enough entropy has been collected.\n",
            stderr);
    }
    (void)close(fd);
}

#endif

int kdf(const BYTE *raw_key,size_t raw_key_length,
        BYTE *salt_buff,size_t salt_length,BYTE config,BYTE *result,size_t result_length){
    if (raw_key==NULL||salt_buff==NULL)     return 1;
    if (raw_key_length<=0||salt_length<=0||result_length<=0)  return 1;

    /* process 2 bit kdf type */
    int opslimit=((config & 0b00111000)>>3)*2;
    int memlimit=((config & 0b00000111))*100000000*2;
    int kdf_result=1;

    switch (config>>6){
        case ARGON_2I13      :  kdf_result=crypto_pwhash(result,result_length,raw_key,raw_key_length,
                                        salt_buff,opslimit,memlimit,crypto_pwhash_ALG_ARGON2I13);
                                break;
        case ARGON_2ID13     :  kdf_result=crypto_pwhash(result,result_length,raw_key,raw_key_length,
                                        salt_buff,opslimit,memlimit,crypto_pwhash_ALG_ARGON2ID13);
                                break;
        case SCRYPT_S208S256 :  kdf_result=crypto_pwhash_scryptsalsa208sha256(result,result_length,raw_key,
                                        raw_key_length,salt_buff,opslimit,memlimit);
                                break;
        default              :return 1;   
    }
    if (kdf_result!=0)  return kdf_result;
    return 0;
}

int key_file_process(const char *key_file,size_t process_bytes,BYTE kdf_config,
                     size_t result_length,BYTE *result){
    if (key_file==NULL)     return 1;
    if (process_bytes<=0||result_length<=0) return 1;

    FILE *fp_keyfile;
    BYTE *raw_data,*salt_data;
    size_t file_size,salt_length=1024;

    if ((fp_keyfile=fopen(key_file,"rb"))==NULL){
        fprintf(stderr,"Unable to open key file.\n");
        return 1;
    }
    raw_data=malloc(process_bytes);
    CHECK_ALLOC(raw_data);
    salt_data=malloc(1024);
    CHECK_ALLOC(raw_data);
    if ((file_size=get_file_size(key_file))==0){
        fprintf(stderr,"Unable to get key file size(File size is 0).\n");
        return 1;
    }
    if (file_size<process_bytes+1024){
        fprintf(stderr,"Key file size is less than required.\n");
        process_bytes=file_size;
    }
    
    fread(raw_data,process_bytes,1,fp_keyfile);
    if (fread(salt_data,1024,1,fp_keyfile)<=1024){
        rewind(fp_keyfile);
        salt_length=file_size;
        fread(salt_data,file_size,1,fp_keyfile);
    }
    if (kdf(raw_data,process_bytes,salt_data,salt_length,kdf_config,result,result_length)!=0){
        fprintf(stderr,"Unable to process key file.\n");
        return 1;
    }

    free(raw_data);
    free(salt_data);
    fclose(fp_keyfile);
    return 0;
}

struct head_t *read_file_header(FILE *fp,struct head_t **head_ptr){
    /* file header is always 22 bytes,so just read it */
    unsigned char *raw_buff=calloc(24,1);
    if (fread(raw_buff,24,1,fp)!=24){
        fprintf(stderr,"Invalid file.File too short.\n");
        return NULL;
    }
}

int pow(int a,int b){
    int result=a;
    for (int i=0;i<b;i++){
        a*=a;
    }
    if (result<a)   return -1;  /* overflow */
    return result;
}