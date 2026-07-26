#include <stdio.h>
#include <sys/auxv.h>
#include <unistd.h>
int main(void) {
    unsigned char *r = (unsigned char *)getauxval(AT_RANDOM);
    printf("AT_SECURE=%ld AT_UID=%ld AT_EUID=%ld getuid=%d geteuid=%d\n",
           (long)getauxval(AT_SECURE), (long)getauxval(AT_UID),
           (long)getauxval(AT_EUID), (int)getuid(), (int)geteuid());
    printf("AT_RANDOM=%02x%02x%02x%02x\n", r[0], r[1], r[2], r[3]);
    return 0;
}
