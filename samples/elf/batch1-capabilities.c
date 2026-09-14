#include <dlfcn.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

int exported_batch1_function(const char *value) {
    void *handle = dlopen("libm.so.6", RTLD_LAZY);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    const char *path = getenv("PATH");
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    SSL_CTX *ssl = SSL_CTX_new(TLS_method());
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page != MAP_FAILED) mprotect(page, 4096, PROT_READ);
    if (ssl) SSL_CTX_free(ssl);
    if (ctx) EVP_MD_CTX_free(ctx);
    if (handle) dlclose(handle);
    if (fd >= 0) close(fd);
    return value && path ? 0 : 1;
}

int main(int argc, char **argv) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%s", argc > 1 ? argv[1] : "batch1");
    return exported_batch1_function(buffer);
}
