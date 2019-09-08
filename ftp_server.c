#include <sys/socket.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <dirent.h>
#include <errno.h>

const char *BASE_DIR_FROM_HOME = "/ftp";

// File system auxiliar functions
void get_base_dir(char *base_path);

int main() {
    char base_path[100];
    get_base_dir(base_path);
    printf("Base directory at: %s\n", base_path);



    return 0;
}


void get_base_dir(char *base_path) {
    struct passwd* pw = getpwuid(getuid());
    const char *home_dir = pw->pw_dir;
    strcpy(base_path, home_dir); 
    strcat(base_path, BASE_DIR_FROM_HOME);
    DIR *base_dir = opendir(base_path);
    if (base_dir) {
        closedir(base_dir);
    } else if (ENOENT == errno) {
        int child;
        if (child = fork()) {
            waitpid(child, NULL, 0);
        } else {
            char *args[] = {"mkdir", "-p", base_path, NULL};
            execv("/bin/mkdir", args);
        }
    }
}
