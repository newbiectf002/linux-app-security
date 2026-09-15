#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern int capset(void *, void *);
#ifdef MILESTONE5_SHARED
int system(const char *command) { return command ? 0 : -1; }
#endif

__attribute__((visibility("default")))
int milestone5_capabilities(const char *path, char *const argv[]) {
    int fd = open(path, O_RDONLY);
    FILE *stream = fopen(path, "r");
    void *handle = dlopen("libm.so.6", RTLD_LAZY);
    void *symbol = handle ? dlsym(handle, "cos") : NULL;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (path == NULL) {
        system("true");
        popen("true", "r");
        execve("/bin/true", argv, argv);
        execvp("true", argv);
        execl("/bin/true", "true", NULL);
        posix_spawn(NULL, "/bin/true", NULL, NULL, argv, argv);
        fork();
        clone(NULL, NULL, 0, NULL);
        kill(0, 0);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        openat(AT_FDCWD, path, O_RDONLY);
        unlink(path);
        chmod(path, 0600);
        chown(path, 0, 0);
        rename(path, path);
        connect(sock, NULL, 0);
        bind(sock, NULL, 0);
        listen(sock, 1);
        accept(sock, NULL, NULL);
        send(sock, path, 0, 0);
        recv(sock, NULL, 0, 0);
        getaddrinfo(NULL, NULL, NULL, NULL);
        setuid(0);
        setgid(0);
        setresuid(0, 0, 0);
        capset(NULL, NULL);
        mprotect(page, 4096, PROT_READ);
    }
    if (page != MAP_FAILED) munmap(page, 4096);
    if (handle) dlclose(handle);
    if (stream) fclose(stream);
    if (fd >= 0) close(fd);
    if (sock >= 0) close(sock);
    return symbol != NULL;
}

#ifndef MILESTONE5_SHARED
int main(int argc, char **argv) {
    return milestone5_capabilities(argc > 1 ? argv[1] : ".", argv);
}
#endif
