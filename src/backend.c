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