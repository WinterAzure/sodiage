#include "utils.h"

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
    printf("Input message:\n");
    *message_text=NULL;
    char *message_line=NULL;
    size_t size=0,total_size=0;
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