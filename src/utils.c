#include "utils.h"
#include "dictionary.h"

int getpassword(const char *prompt,char *password_save_buff){
    struct termios term;
    printf("%s",prompt);
    if (tcgetattr(fileno(stdin), &term)<0)
        return -1;
    term.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(stdin), 0, &term)<0)
        return -1;
    password_save_buff=sodium_malloc(256*sizeof(char));
    if (password_save_buff==NULL)
        return -1;
    fgets(password_save_buff, 256*sizeof(char), stdin);
    if (password_save_buff[strlen(password_save_buff)+1]=='\n')
        password_save_buff[strlen(password_save_buff)+1]='\0';
    term.c_lflag |= ECHO;
    tcsetattr(fileno(stdin), 0, &term);
    return 0;
}

size_t get_inputtext(char **message_text){
    *message_text=NULL;
    char *message_line=NULL;
    size_t size=0,total_size=0;

    printf("Input message:\n");
    fgetc(stdin);
    while (getline(&message_line,&size,stdin)){
        if (strcmp(message_line,"\n")==0)   break;
        total_size+=size;
        *message_text=realloc(*message_text,total_size+1);
        CHECK_ALLOC(*message_text);
        strcat(*message_text,message_line);
    }
    return strlen(*message_text);
}

const char *generate_password_random(int size,char **target){
    if (size<=0)    return NULL;

    BYTE *random_buff=sodium_malloc(size*2);
    char *ptr_password=*target;
    int counter=0;    

    CHECK_ALLOC(random_buff);
    randombytes(random_buff,size*2);
    *target=sodium_malloc(size*sizeof(char));
    for (BYTE *ptr=random_buff;ptr!=random_buff+size;ptr++){
        if (*ptr>=33 && *ptr<=126){
            *ptr_password=*ptr;
            ptr_password++;counter++;
        }
        if (counter==32)
            return ptr_password;
    }
    sodium_free(random_buff);
    return NULL;
}

const char *generate_password_meaningful(int word_size,char dlm,char **target){
    if (word_size>16||word_size<0)  return NULL;
    if (dlm<33||dlm>126)            return NULL;
    *target=NULL;
    char *word=malloc(1024);
    CHECK_ALLOC(word);
    int total_size=0;
    for (int i=0;i<word_size;i++){
        int index=rand()%153;
        strcpy(word,password_words[index]);
        word[strlen(word)+1]=dlm;
        total_size+=strlen(word)+1;
        *target=realloc(*target,total_size+1);
        CHECK_ALLOC(*target);
        strcat(*target,word);
    }
    free(word);
    return *target;
}

void print_as_base64(const char *start,const void *data,size_t data_size,const char *end){
    if (data_size<=0){
        fprintf(stderr,"Invaild usage. Data size is negative.\n");
        return;
    }
    if (start==NULL||end==NULL){
        start="";end="";
    }
    size_t encoded_length=base64_encoded_length(data_size);
    char *base64_encoded_string=malloc(encoded_length);
    CHECK_ALLOC(base64_encoded_string);
    if (base64_encode(base64_encoded_string,encoded_length,data,data_size)==-1){
        fprintf(stderr,"Error : unable to encode base64 string.\n");
        free(base64_encoded_string);
        return;
    }
    printf("%s\n%s\n%s\n",start,base64_encoded_string,end);
}

const size_t get_file_size(const char *file_name){
    struct stat f_stat;
    if (stat(file_name,&f_stat)!=0)
        return 0;
    return f_stat.st_size;
}