#ifndef __GLOBAL_H
#define __GLOBAL_H

struct config_arguments_st{
    int mode;
    char *raw_file;
    char *output_file;
};

extern struct config_arguments_st config_arguments;
    

#endif