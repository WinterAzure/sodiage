#include "../src/utils.h"

#define TEST_SUCCEED    1
#define TEST_FAILED     0

#define TEST(X)     if ((X())==TEST_SUCCEED){                 \
                        total+=1;passed+=1;                 \
                        printf("Test:%d succeed!\n",total); \
                    }else{                                  \
                        total+=1;                           \
                        printf("Test:%d failed. line %d.\n",total,__LINE__);    \
                    }

int test__generate_password_random_1(){
    char *target=NULL;
    generate_password_random(24,&target);
    if (target==NULL)   return TEST_SUCCEED;
    return TEST_FAILED;
}

int test__generate_password_random_2(){
    char *target=NULL;
    generate_password_random(12,&target);
    if (target==NULL)   return TEST_FAILED;
    if (strlen(target)!=24) return TEST_FAILED;
    return TEST_SUCCEED;
}

int test__generate_password_random_3(){
    char *target=NULL;
    char *result=generate_password_random(12,&target);
    if (target==NULL||result==NULL)     return TEST_FAILED;
    if (strcmp(target,result)!=0)       return TEST_FAILED;
    return TEST_SUCCEED;
}

int main(){
    int total=0;
    int passed=0;
    TEST(test__generate_password_random_1);
    TEST(test__generate_password_random_2);
    TEST(test__generate_password_random_3);
    printf("===============\n");
    printf("Total:%d\n",total);
    printf("Failed:%d\tSucceed:%d\n",total-passed,passed);
    return 0;
}