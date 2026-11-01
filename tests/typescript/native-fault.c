/* Test-only syscall boundary faults. Never linked into the distributed addon. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int openat(int directory, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    int (*real_openat)(int, const char *, int, ...) = dlsym(RTLD_NEXT, "openat");
    const char *selected = getenv("FALCON_TEST_SWAP_PARENT");
    const char *moved = getenv("FALCON_TEST_MOVED_PARENT");
    const char *replacement = getenv("FALCON_TEST_REPLACEMENT");
    if (selected && moved && replacement && strcmp(path, "writes.log") == 0) {
        if (rename(selected, moved) < 0 || symlink(replacement, selected) < 0) return -1;
    }
    return real_openat(directory, path, flags, mode);
}

static int selected(int fd) {
    const char *path = getenv("FALCON_TEST_FILE");
    struct stat actual, expected;
    return path && fstat(fd, &actual) == 0 && stat(path, &expected) == 0 &&
        actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino;
}

ssize_t write(int fd, const void *data, size_t size) {
    static int count;
    ssize_t (*real_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    if (selected(fd)) {
        if (++count == 1) { errno = EINTR; return -1; }
        if (count == 2 && size > 3) size = 3;
    }
    return real_write(fd, data, size);
}

int fsync(int fd) {
    static int count;
    static int directory_count;
    int (*real_fsync)(int) = dlsym(RTLD_NEXT, "fsync");
    const char *fault = getenv("FALCON_TEST_FAULT");
    const char *directory = getenv("FALCON_TEST_DIRECTORY");
    struct stat actual, expected;
    if (directory && fstat(fd, &actual) == 0 && stat(directory, &expected) == 0 &&
        actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino &&
        ++directory_count > 1 && fault && strcmp(fault, "directory-flush-failure") == 0) {
        errno = EIO;
        return -1;
    }
    if (selected(fd) && ++count > 1) {
        if (fault && strcmp(fault, "flush-failure") == 0) { errno = EIO; return -1; }
        if (count == 2) { errno = EINTR; return -1; }
    }
    return real_fsync(fd);
}
