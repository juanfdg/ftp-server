#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <pwd.h>

const char *BASE_DIR_FROM_HOME = "/ftp";

int main() {
    struct passwd* pw = getpwuid(getuid());
    const char *home_dir = pw->pw_dir;
    char base_path[100];
    strcpy(base_path, home_dir); 
    strcat(base_path, BASE_DIR_FROM_HOME);

    printf("Base directory at: %s\n", base_path);
    return 0;
}
