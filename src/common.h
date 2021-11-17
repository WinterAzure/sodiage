#ifndef __COMMON_H
#define __COMMON_H

#define ERROR(MSG)  fprintf(stderr,MSG)

#define CHUNK_SIZE 4096

#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

enum ConfigOperateMode {ENCRYPT,DECRYPT};

#include "global.h"

#endif