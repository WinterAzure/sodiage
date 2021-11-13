#include "hmacutil.h"

void hmac_interactive_wizard(){
    printf("Choose Hash Algorithm?\n");
    printf("0.MD4   1.MD5\n");
    printf("2.SHA1  3.SHA224    4.SHA256    5.SHA384    6.SHA512\n");
    printf("7.SHA3_224  8.SHA3_256  9.SHA3_384  A.SHA3_512\n");
    int choose=fgetc(stdin)-48;
    if (choose==17)
        choose=10;
    if (choose>10||choose<0){
        fprintf(stderr,"Invalid choose %d.\n",choose);
        return;
    }
    const EVP_MD *engine=evp_init[choose]();

    char *message_text=NULL;
    if (get_inputtext(&message_text)==0){
        fprintf(stderr,"No message provided,exit.\n");
        return;
    }

    char *password_buff;
    if (getpassword("Enter password[Max 256 chars]: ",&password_buff)!=0){
        fprintf(stderr,"Unable to get password.\n");
        return;
    }

    unsigned char output[EVP_MAX_MD_SIZE]={0};
    unsigned int length_output=0;
    CHECK_ALLOC(output);
    HMAC_CTX *ctx=HMAC_CTX_new();
    HMAC_Init_ex(ctx,password_buff,256*sizeof(char),engine,NULL);
    HMAC_Update(ctx,(const BYTE *)message_text,strlen(message_text));
    HMAC_Final(ctx,output,&length_output);
    free(message_text);

    print_detail(output,&length_output);
}

void print_detail(BYTE *data,unsigned int *size){
    if (size==NULL||*size<=0)   return;
    printf("\n==================\n");
    printf("HMAC Length: %d\n",*size);
    printf("HMAC Digist: ");
    for (int i=0;i<*size;i++)
        printf("%03x",(unsigned int)data[i]);
    putc('\n',stdout);
}