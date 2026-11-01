#define _GNU_SOURCE
#define NAPI_VERSION 8
#include <node_api.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    int directory;
    int file;
    int locked;
    int failed;
} retained;

static const napi_type_tag handle_tag = {0xfed76bce03974d12ULL, 0x9aa76d5c612158fbULL};

static void release(napi_env env, void *data, void *hint) {
    (void)env;
    (void)hint;
    retained *h = data;
    if (h->file >= 0) close(h->file);
    if (h->directory >= 0) close(h->directory);
    free(h);
}

static napi_value fail(napi_env env, const char *code) {
    napi_throw_error(env, code, "RTR filesystem operation refused");
    return NULL;
}

static int durable(int fd) {
    int result;
    do { result = fsync(fd); } while (result < 0 && errno == EINTR);
    return result;
}

static int safe_file(int fd) {
    struct stat s;
    return fstat(fd, &s) == 0 && S_ISREG(s.st_mode) && s.st_nlink == 1 &&
           s.st_uid == getuid() && !(s.st_mode & 0077);
}

static int safe_directory(int fd) {
    struct stat s;
    return fstat(fd, &s) == 0 && S_ISDIR(s.st_mode) &&
           s.st_uid == getuid() && !(s.st_mode & 0022);
}

static retained *handle(napi_env env, napi_value value) {
    bool tagged = false;
    retained *h = NULL;
    if (napi_check_object_type_tag(env, value, &handle_tag, &tagged) != napi_ok ||
        !tagged || napi_unwrap(env, value, (void **)&h) != napi_ok || !h ||
        h->file < 0 || h->failed) {
        fail(env, "CONFIG_INSECURE");
        return NULL;
    }
    return h;
}

static napi_value open_retained(napi_env env, napi_callback_info info) {
    size_t argc = 2, length = 0;
    napi_value args[2], result;
    bool locked;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 2 ||
        napi_get_value_string_utf8(env, args[0], NULL, 0, &length) != napi_ok ||
        length == 0 || length > 4096 ||
        napi_get_value_bool(env, args[1], &locked) != napi_ok)
        return fail(env, "CONFIG_INSECURE");
    char path[4097];
    size_t copied;
    if (napi_get_value_string_utf8(env, args[0], path, sizeof(path), &copied) != napi_ok ||
        copied != length || strlen(path) != length || path[0] != '/' || path[length-1] == '/')
        return fail(env, "CONFIG_INSECURE");
    /* Reject lexical aliases before splitting, including empty components. */
    for (char *p = path + 1; ; ) {
        char *end = strchr(p, '/');
        size_t n = end ? (size_t)(end-p) : strlen(p);
        if (!n || (n == 1 && p[0] == '.') || (n == 2 && p[0] == '.' && p[1] == '.'))
            return fail(env, "CONFIG_INSECURE");
        if (!end) break;
        p = end + 1;
    }
    retained *h = calloc(1, sizeof(*h));
    if (!h) return fail(env, "CONFIG_INSECURE");
    h->directory = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    h->file = -1;
    h->locked = locked;
    if (h->directory < 0) goto insecure;
    char *part = path + 1, *separator;
    while ((separator = strchr(part, '/'))) {
        struct stat s;
        if (fstat(h->directory, &s) < 0 ||
            (s.st_uid != 0 && s.st_uid != getuid()) ||
            ((s.st_mode & 0022) && !(s.st_mode & S_ISVTX))) goto insecure;
        *separator = '\0';
        int next = openat(h->directory, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 && errno == ENOENT) {
            if (mkdirat(h->directory, part, 0700) < 0 && errno != EEXIST) goto insecure;
            if (durable(h->directory) < 0) goto insecure;
            next = openat(h->directory, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (next < 0) goto insecure;
        close(h->directory);
        h->directory = next;
        part = separator + 1;
    }
    if (!safe_directory(h->directory)) goto insecure;
    h->file = openat(h->directory, part,
                     O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    if (h->file < 0 || !safe_file(h->file)) goto insecure;
    if (locked && flock(h->file, LOCK_EX | LOCK_NB) < 0) {
        int busy = errno == EWOULDBLOCK || errno == EAGAIN;
        release(env, h, NULL);
        return fail(env, busy ? "READ_ONLY_VIOLATION" : "CONFIG_INSECURE");
    }
    if (durable(h->file) < 0 || durable(h->directory) < 0) goto insecure;
    if (napi_create_object(env, &result) != napi_ok ||
        napi_type_tag_object(env, result, &handle_tag) != napi_ok ||
        napi_wrap(env, result, h, release, NULL, NULL) != napi_ok) goto insecure;
    return result;
insecure:
    release(env, h, NULL);
    return fail(env, "CONFIG_INSECURE");
}

static napi_value append(napi_env env, napi_callback_info info) {
    size_t argc = 2, length;
    napi_value args[2], result;
    void *data;
    bool buffer = false;
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok || argc != 2 ||
        napi_is_buffer(env, args[1], &buffer) != napi_ok || !buffer ||
        napi_get_buffer_info(env, args[1], &data, &length) != napi_ok)
        return fail(env, "CONFIG_INSECURE");
    retained *h = handle(env, args[0]);
    if (!h) return NULL;
    if (h->locked || !safe_file(h->file) || !safe_directory(h->directory))
        return fail(env, "CONFIG_INSECURE");
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(h->file, (char *)data + written, length - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) goto uncertain;
        written += (size_t)count;
    }
    if (durable(h->file) < 0 || durable(h->directory) < 0) goto uncertain;
    napi_get_undefined(env, &result);
    return result;
uncertain:
    /* Never replay a partially written or unconfirmed record on this handle. */
    h->failed = 1;
    return fail(env, "CONFIG_INSECURE");
}

static napi_value close_retained(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value arg, result;
    bool tagged = false;
    retained *h = NULL;
    if (napi_get_cb_info(env, info, &argc, &arg, NULL, NULL) != napi_ok || argc != 1 ||
        napi_check_object_type_tag(env, arg, &handle_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, arg, (void **)&h) != napi_ok || !h)
        return fail(env, "CONFIG_INSECURE");
    /* close is idempotent, including after append failure. Do not retry close(EINTR). */
    if (h->file >= 0) { close(h->file); h->file = -1; }
    if (h->directory >= 0) { close(h->directory); h->directory = -1; }
    napi_get_undefined(env, &result);
    return result;
}
#endif

NAPI_MODULE_INIT() {
#ifdef _WIN32
    /* A loadable Windows artifact, with no POSIX entry points or emulation. */
    (void)env;
    return exports;
#else
    napi_property_descriptor methods[] = {
        {"open", NULL, open_retained, NULL, NULL, NULL, napi_default, NULL},
        {"append", NULL, append, NULL, NULL, NULL, napi_default, NULL},
        {"close", NULL, close_retained, NULL, NULL, NULL, napi_default, NULL}
    };
    if (napi_define_properties(env, exports, 3, methods) != napi_ok) return NULL;
    return exports;
#endif
}
