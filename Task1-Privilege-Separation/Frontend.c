#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define SOCKET_PATH "/tmp/privsep_auth.sock"
#define PROTOCOL_MAGIC UINT32_C(0x41555448)
#define OP_VALIDATE UINT32_C(1)
#define OP_INVALID_TEST UINT32_C(999)
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

static int read_line(const char *prompt, char *buffer, size_t size)
{
    size_t length;
    int character;

    printf("%s", prompt);
    fflush(stdout);

    if (fgets(buffer, (int)size, stdin) == NULL) {
        return -1;
    }

    length = strlen(buffer);
    if (length > 0 && buffer[length - 1] == '\n') {
        buffer[length - 1] = '\0';
        return buffer[0] == '\0' ? -1 : 0;
    }

    character = getchar();
    if (character == '\n' || character == EOF) {
        return buffer[0] == '\0' ? -1 : 0;
    }

    while ((character = getchar()) != '\n' && character != EOF) {
    }
    errno = EMSGSIZE;
    return -1;
}

static int read_password(char *buffer, size_t size)
{
    struct termios original;
    struct termios hidden;
    sigset_t blocked;
    sigset_t previous;
    int terminal_changed = 0;
    int result;

    sigemptyset(&blocked);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGTERM);
    sigaddset(&blocked, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &blocked, &previous) == -1) {
        return -1;
    }

    if (isatty(STDIN_FILENO) &&
        tcgetattr(STDIN_FILENO, &original) == 0) {
        hidden = original;
        hidden.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0) {
            terminal_changed = 1;
        }
    }

    result = read_line("Password: ", buffer, size);

    if (terminal_changed) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
        putchar('\n');
    }
    (void)sigprocmask(SIG_SETMASK, &previous, NULL);

    return result;
}

static int create_password_buffer(char *name, size_t name_size)
{
    struct timespec now;
    unsigned int attempt;

    if (clock_gettime(CLOCK_REALTIME, &now) == -1) {
        return -1;
    }

    for (attempt = 0; attempt < 100; attempt++) {
        int fd;

        snprintf(name, name_size, "/authpw_%lu_%ld_%lu_%u",
                 (unsigned long)getuid(), (long)getpid(),
                 (unsigned long)now.tv_nsec, attempt);

        fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        if (fd >= 0) {
            if (ftruncate(fd, PASSWORD_BUFFER_SIZE) == -1 ||
                fchmod(fd, 0600) == -1) {
                int saved_errno = errno;
                close(fd);
                shm_unlink(name);
                errno = saved_errno;
                return -1;
            }
            return fd;
        }

        if (errno != EEXIST) {
            return -1;
        }
    }

    errno = EEXIST;
    return -1;
}

int main(int argc, char *argv[])
{
    struct auth_request request;
    struct auth_response response;
    struct sockaddr_un address;
    char *password = MAP_FAILED;
    int shared_fd = -1;
    int socket_fd = -1;
    int invalid_operation = 0;
    int result = EXIT_FAILURE;

    if (argc == 2 && strcmp(argv[1], "--invalid-op") == 0) {
        invalid_operation = 1;
    } else if (argc != 1) {
        fprintf(stderr, "Usage: %s [--invalid-op]\n", argv[0]);
        return EXIT_FAILURE;
    }

    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));

    if (read_line("Username: ", request.username,
                  sizeof(request.username)) == -1) {
        fprintf(stderr, "Invalid or overlong username\n");
        goto cleanup;
    }

    shared_fd = create_password_buffer(request.shm_name,
                                       sizeof(request.shm_name));
    if (shared_fd == -1) {
        perror("create shared password buffer");
        goto cleanup;
    }

    password = mmap(NULL, PASSWORD_BUFFER_SIZE,
                    PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd, 0);
    if (password == MAP_FAILED) {
        perror("mmap password buffer");
        goto cleanup;
    }

    (void)mlock(password, PASSWORD_BUFFER_SIZE);
#ifdef MADV_DONTDUMP
    (void)madvise(password, PASSWORD_BUFFER_SIZE, MADV_DONTDUMP);
#endif

    if (read_password(password, PASSWORD_BUFFER_SIZE) == -1) {
        fprintf(stderr, "Invalid or overlong password\n");
        goto cleanup;
    }

    request.magic = PROTOCOL_MAGIC;
    request.operation = invalid_operation ? OP_INVALID_TEST : OP_VALIDATE;
    request.password_length = (uint32_t)strlen(password);
    request.owner_uid = getuid();

    socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socket_fd == -1) {
        perror("socket");
        goto cleanup;
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, sizeof(address.sun_path), "%s", SOCKET_PATH);

    if (connect(socket_fd, (struct sockaddr *)&address,
                sizeof(address)) == -1) {
        perror("connect");
        goto cleanup;
    }

    if (send_full(socket_fd, &request, sizeof(request)) == -1) {
        perror("send request");
        goto cleanup;
    }

    if (recv_full(socket_fd, &response, sizeof(response)) == -1) {
        perror("receive response");
        goto cleanup;
    }

    if (response.magic != PROTOCOL_MAGIC) {
        fprintf(stderr, "Rejected malformed backend response\n");
        goto cleanup;
    }

    printf("Authentication result: %s\n", response.message);
    result = response.accepted ? EXIT_SUCCESS : EXIT_FAILURE;

cleanup:
    if (socket_fd != -1) {
        close(socket_fd);
    }
    if (password != MAP_FAILED) {
        secure_wipe(password, PASSWORD_BUFFER_SIZE);
        (void)msync(password, PASSWORD_BUFFER_SIZE, MS_SYNC);
        (void)munlock(password, PASSWORD_BUFFER_SIZE);
        munmap(password, PASSWORD_BUFFER_SIZE);
    }
    if (shared_fd != -1) {
        close(shared_fd);
    }
    if (request.shm_name[0] != '\0' &&
        shm_unlink(request.shm_name) == -1 &&
        errno != ENOENT) {
        perror("shm_unlink");
    }
    secure_wipe(&request, sizeof(request));
    return result;
}
