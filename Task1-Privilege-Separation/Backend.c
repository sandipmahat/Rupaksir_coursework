#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_PATH "/tmp/privsep_auth.sock"
#define PROTOCOL_MAGIC UINT32_C(0x41555448)
#define OP_VALIDATE UINT32_C(1)
#define MAX_USERNAME 32
#define MAX_PASSWORD 127
#define PASSWORD_BUFFER_SIZE (MAX_PASSWORD + 1)
#define MAX_SHM_NAME 64

struct auth_request {
    uint32_t magic;
    uint32_t operation;
    uint32_t password_length;
    uid_t owner_uid;
    char username[MAX_USERNAME];
    char shm_name[MAX_SHM_NAME];
};

struct auth_response {
    uint32_t magic;
    uint32_t accepted;
    char message[96];
};

static volatile sig_atomic_t stop_requested;

/*
 * noinline makes the wipe easy to identify in `make disassembly` output.
 * explicit_bzero(), or the volatile fallback, prevents dead-store removal.
 */
#if defined(__GNUC__)
__attribute__((noinline))
#endif
static void secure_wipe(void *ptr, size_t length)
{
#if defined(__GLIBC__)
    explicit_bzero(ptr, length);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (length-- > 0) {
        *p++ = 0;
    }
#endif
}

static int recv_full(int fd, void *buffer, size_t length)
{
    unsigned char *p = (unsigned char *)buffer;

    while (length > 0) {
        ssize_t received = recv(fd, p, length, 0);

        if (received == 0) {
            return -1;
        }
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        p += received;
        length -= (size_t)received;
    }

    return 0;
}

static int send_full(int fd, const void *buffer, size_t length)
{
    const unsigned char *p = (const unsigned char *)buffer;

    while (length > 0) {
        ssize_t sent = send(fd, p, length, MSG_NOSIGNAL);

        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (sent == 0) {
            return -1;
        }

        p += sent;
        length -= (size_t)sent;
    }

    return 0;
}

static int parse_id(const char *text, unsigned long *value)
{
    char *end = NULL;
    unsigned long parsed;

    if (text == NULL || *text == '\0' || *text == '-') {
        return -1;
    }

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return -1;
    }

    *value = parsed;
    return 0;
}

/*
 * With a set-user-ID launch, the real IDs identify the caller. With sudo,
 * SUDO_UID/SUDO_GID identify the invoking user because sudo normally makes
 * all three process UIDs root. A direct root launch falls back to nobody.
 */
static int choose_unprivileged_identity(uid_t *target_uid, gid_t *target_gid)
{
    unsigned long sudo_uid;
    unsigned long sudo_gid;

    if (geteuid() != 0) {
        *target_uid = getuid();
        *target_gid = getgid();
        return 0;
    }

    if (getuid() != 0) {
        *target_uid = getuid();
        *target_gid = getgid();
        return 0;
    }

    if (parse_id(getenv("SUDO_UID"), &sudo_uid) == 0 &&
        parse_id(getenv("SUDO_GID"), &sudo_gid) == 0 &&
        sudo_uid > 0 &&
        (uid_t)sudo_uid == sudo_uid &&
        (gid_t)sudo_gid == sudo_gid) {
        *target_uid = (uid_t)sudo_uid;
        *target_gid = (gid_t)sudo_gid;
        return 0;
    }

    {
        struct passwd *account = getpwnam("nobody");
        if (account == NULL) {
            fprintf(stderr, "Cannot find an unprivileged account\n");
            return -1;
        }
        *target_uid = account->pw_uid;
        *target_gid = account->pw_gid;
    }

    return 0;
}

static int drop_privileges_permanently(uid_t target_uid, gid_t target_gid)
{
    printf("Backend IDs before drop: ruid=%ld euid=%ld\n",
           (long)getuid(), (long)geteuid());

    if (geteuid() == 0) {
        /* Root supplementary groups must not survive the UID/GID change. */
        if (setgroups(0, NULL) == -1) {
            perror("setgroups");
            return -1;
        }
        if (setresgid(target_gid, target_gid, target_gid) == -1) {
            perror("setresgid");
            return -1;
        }
        if (setresuid(target_uid, target_uid, target_uid) == -1) {
            perror("setresuid");
            return -1;
        }
    }

    printf("Backend IDs after drop:  ruid=%ld euid=%ld\n",
           (long)getuid(), (long)geteuid());

    if (getuid() != target_uid || geteuid() != target_uid ||
        getgid() != target_gid || getegid() != target_gid) {
        fprintf(stderr, "Privilege drop verification failed\n");
        return -1;
    }

    errno = 0;
    if (target_uid != 0 && seteuid(0) == 0) {
        fprintf(stderr, "Privilege drop was reversible\n");
        return -1;
    }

    printf("Runtime check: permanent privilege drop verified\n");
    return 0;
}

static int get_peer_uid(int fd, uid_t *peer_uid)
{
    struct ucred credentials;
    socklen_t length = sizeof(credentials);

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED,
                   &credentials, &length) == -1 ||
        length != sizeof(credentials)) {
        return -1;
    }

    *peer_uid = credentials.uid;
    return 0;
}

static int valid_shm_name(const char *name)
{
    size_t i;

    if (name[0] != '/' || name[1] == '\0' ||
        memchr(name, '\0', MAX_SHM_NAME) == NULL) {
        return 0;
    }

    for (i = 1; name[i] != '\0'; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!isalnum(c) && c != '_') {
            return 0;
        }
    }

    return 1;
}

static int constant_time_password_equal(const char *supplied,
                                        size_t supplied_length,
                                        const char *expected)
{
    size_t expected_length = strlen(expected);
    unsigned char difference = 0;
    size_t i;

    if (supplied_length != expected_length) {
        return 0;
    }

    for (i = 0; i < expected_length; i++) {
        difference |= (unsigned char)supplied[i] ^
                      (unsigned char)expected[i];
    }

    return difference == 0;
}

static int validate_password(const char *username,
                             const char *password,
                             size_t password_length)
{
    if (strcmp(username, "student") != 0) {
        return 0;
    }

    return constant_time_password_equal(password, password_length,
                                        "SecurePass123");
}

static void set_response(struct auth_response *response,
                         int accepted,
                         const char *message)
{
    response->magic = PROTOCOL_MAGIC;
    response->accepted = accepted ? 1U : 0U;
    snprintf(response->message, sizeof(response->message), "%s", message);
}

static void handle_client(int client_fd)
{
    struct auth_request request;
    struct auth_response response;
    struct stat shared_stat;
    struct timeval timeout = { 5, 0 };
    uid_t peer_uid;
    int shared_fd = -1;
    char *password = MAP_FAILED;
    int accepted = 0;

    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    set_response(&response, 0, "authentication rejected");

    (void)setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
                     &timeout, sizeof(timeout));

    if (recv_full(client_fd, &request, sizeof(request)) == -1) {
        set_response(&response, 0, "rejected: malformed request framing");
        goto finished;
    }

    if (get_peer_uid(client_fd, &peer_uid) == -1) {
        set_response(&response, 0, "rejected: cannot verify peer");
        goto finished;
    }

    if (request.magic != PROTOCOL_MAGIC ||
        request.operation != OP_VALIDATE) {
        set_response(&response, 0, "rejected: not a validation request");
        goto finished;
    }

    if (request.owner_uid != peer_uid) {
        set_response(&response, 0, "rejected: UID mismatch");
        goto finished;
    }

    if (request.password_length == 0 ||
        request.password_length > MAX_PASSWORD ||
        request.username[0] == '\0' ||
        memchr(request.username, '\0', MAX_USERNAME) == NULL ||
        !valid_shm_name(request.shm_name)) {
        set_response(&response, 0, "rejected: invalid request fields");
        goto finished;
    }

    shared_fd = shm_open(request.shm_name,
                         O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0);
    if (shared_fd == -1) {
        set_response(&response, 0, "rejected: cannot open password buffer");
        goto finished;
    }

    if (fstat(shared_fd, &shared_stat) == -1 ||
        shared_stat.st_uid != peer_uid ||
        shared_stat.st_size != PASSWORD_BUFFER_SIZE ||
        (shared_stat.st_mode & 077) != 0) {
        set_response(&response, 0, "rejected: unsafe password buffer");
        goto finished;
    }

    /*
     * Remove the name after opening it. Existing mappings remain valid, while
     * new processes can no longer open or replay this password object.
     */
    if (shm_unlink(request.shm_name) == -1) {
        set_response(&response, 0, "rejected: cannot consume password buffer");
        goto finished;
    }

    password = mmap(NULL, PASSWORD_BUFFER_SIZE,
                    PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd, 0);
    if (password == MAP_FAILED) {
        set_response(&response, 0, "rejected: cannot map password buffer");
        goto finished;
    }

    if (password[request.password_length] != '\0') {
        set_response(&response, 0, "rejected: malformed password buffer");
        goto finished;
    }

    accepted = validate_password(request.username, password,
                                 request.password_length);
    set_response(&response, accepted,
                 accepted ? "authentication accepted"
                          : "authentication rejected");

finished:
    if (password != MAP_FAILED) {
        secure_wipe(password, PASSWORD_BUFFER_SIZE);
        (void)msync(password, PASSWORD_BUFFER_SIZE, MS_SYNC);
        munmap(password, PASSWORD_BUFFER_SIZE);
    }
    if (shared_fd != -1) {
        close(shared_fd);
    }

    (void)send_full(client_fd, &response, sizeof(response));
    secure_wipe(&request, sizeof(request));
}

static int remove_stale_socket(void)
{
    struct stat path_stat;

    if (lstat(SOCKET_PATH, &path_stat) == -1) {
        return errno == ENOENT ? 0 : -1;
    }

    if (!S_ISSOCK(path_stat.st_mode)) {
        errno = EEXIST;
        return -1;
    }

    return unlink(SOCKET_PATH);
}

static void handle_stop_signal(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

int main(void)
{
    struct sockaddr_un address;
    struct sigaction action;
    uid_t target_uid;
    gid_t target_gid;
    int server_fd = -1;
    int result = EXIT_FAILURE;

    if (choose_unprivileged_identity(&target_uid, &target_gid) == -1) {
        return EXIT_FAILURE;
    }

    umask(0077);
    server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_fd == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

    if (remove_stale_socket() == -1) {
        perror("remove stale socket");
        goto cleanup;
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", SOCKET_PATH);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
        perror("bind");
        goto cleanup;
    }

    if (chown(SOCKET_PATH, target_uid, target_gid) == -1 ||
        chmod(SOCKET_PATH, 0600) == -1) {
        perror("secure socket permissions");
        goto cleanup;
    }

    if (listen(server_fd, 16) == -1) {
        perror("listen");
        goto cleanup;
    }

    if (drop_privileges_permanently(target_uid, target_gid) == -1) {
        goto cleanup;
    }

    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_stop_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) == -1 ||
        sigaction(SIGTERM, &action, NULL) == -1) {
        perror("sigaction");
        goto cleanup;
    }

    printf("Backend listening on %s\n", SOCKET_PATH);

    while (!stop_requested) {
        int client_fd = accept4(server_fd, NULL, NULL, SOCK_CLOEXEC);

        if (client_fd == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept4");
            goto cleanup;
        }

        handle_client(client_fd);
        close(client_fd);
    }

    result = EXIT_SUCCESS;

cleanup:
    if (server_fd != -1) {
        close(server_fd);
    }
    if (unlink(SOCKET_PATH) == -1 && errno != ENOENT) {
        perror("unlink socket");
    }
    return result;
}
