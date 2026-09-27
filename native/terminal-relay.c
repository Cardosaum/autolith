#define _DARWIN_C_SOURCE
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#ifdef __APPLE__
#include <util.h>
#else
#include <pty.h>
#endif
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define PROMPT_LIMIT 4096

static volatile sig_atomic_t resized;
static volatile sig_atomic_t terminating;
static struct termios saved_terminal;
static bool terminal_changed;

static void on_resize(int signal_number)
{
  (void)signal_number;
  resized = 1;
}

static void on_terminate(int signal_number)
{
  terminating = signal_number;
}

static void restore_terminal(void)
{
  if (terminal_changed)
    tcsetattr(STDIN_FILENO, TCSANOW, &saved_terminal);
}

static bool write_all(int descriptor, const void *source, size_t length)
{
  const unsigned char *bytes = source;
  while (length != 0) {
    ssize_t written = write(descriptor, bytes, length);
    if (written < 0 && errno == EINTR)
      continue;
    if (written <= 0)
      return false;
    bytes += written;
    length -= (size_t)written;
  }
  return true;
}

static bool read_all(int descriptor, void *target, size_t length)
{
  unsigned char *bytes = target;
  while (length != 0) {
    ssize_t count = read(descriptor, bytes, length);
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      return false;
    bytes += count;
    length -= (size_t)count;
  }
  return true;
}

static int approval_listener(const char *path)
{
  struct sockaddr_un address = {0};
  int descriptor;
  bool bound = false;

  if (strlen(path) >= sizeof(address.sun_path))
    return -1;
  descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
  if (descriptor < 0)
    return -1;
  address.sun_family = AF_UNIX;
  strcpy(address.sun_path, path);
  if (bind(descriptor, (struct sockaddr *)&address, sizeof(address)) == 0)
    bound = true;
  if (!bound || chmod(path, 0600) != 0 || listen(descriptor, 8) != 0) {
    close(descriptor);
    if (bound)
      unlink(path);
    return -1;
  }
  return descriptor;
}

static bool challenge_code(char code[7])
{
  unsigned char random_bytes[6];
  int random_file = open("/dev/urandom", O_RDONLY);
  if (random_file < 0)
    return false;
  bool success = read_all(random_file, random_bytes, sizeof(random_bytes));
  close(random_file);
  if (!success)
    return false;
  for (size_t index = 0; index < sizeof(random_bytes); ++index)
    code[index] = (char)('0' + random_bytes[index] % 10);
  code[6] = '\0';
  return true;
}

static bool prompt_for_approval(const char *message, size_t length)
{
  char code[7];
  char answer[32];
  size_t answer_length = 0;
  bool overflow = false;

  if (!challenge_code(code))
    return false;
  tcflush(STDIN_FILENO, TCIFLUSH);
  const char *reset = "\033[?1049l\033[0m\033[2J\033[H";
  const char *heading = "Autolith launcher approval\r\n\r\n";
  if (!write_all(STDOUT_FILENO, reset, strlen(reset)) ||
      !write_all(STDOUT_FILENO, heading, strlen(heading)))
    return false;
  for (size_t index = 0; index < length; ++index) {
    unsigned char character = (unsigned char)message[index];
    if (character >= 32 && character <= 126) {
      if (!write_all(STDOUT_FILENO, &character, 1))
        return false;
    } else if (character == '\n') {
      if (!write_all(STDOUT_FILENO, "\r\n", 2))
        return false;
    } else {
      const char replacement = '?';
      if (!write_all(STDOUT_FILENO, &replacement, 1))
        return false;
    }
  }
  char instruction[160];
  int count = snprintf(instruction, sizeof(instruction),
                       "\r\n\r\nType %s and Enter to approve, or Enter to deny: ", code);
  if (count < 0 || (size_t)count >= sizeof(instruction) ||
      !write_all(STDOUT_FILENO, instruction, (size_t)count))
    return false;
  for (;;) {
    unsigned char character;
    if (!read_all(STDIN_FILENO, &character, 1))
      return false;
    if (character == '\r' || character == '\n')
      break;
    if (character == 127 || character == '\b') {
      if (answer_length != 0) {
        --answer_length;
        write_all(STDOUT_FILENO, "\b \b", 3);
      }
      continue;
    }
    if (character < '0' || character > '9') {
      overflow = true;
      continue;
    }
    if (answer_length >= sizeof(answer)) {
      overflow = true;
      continue;
    }
    answer[answer_length++] = (char)character;
    write_all(STDOUT_FILENO, &character, 1);
  }
  write_all(STDOUT_FILENO, "\r\n", 2);
  tcflush(STDIN_FILENO, TCIFLUSH);
  return !overflow && answer_length == 6 && memcmp(answer, code, 6) == 0;
}

static void serve_approval(int listener, pid_t child)
{
  int connection = accept(listener, NULL, NULL);
  unsigned char length_bytes[4];
  char message[PROMPT_LIMIT];
  uint32_t length;
  char decision = '0';
  struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};

  if (connection < 0)
    return;
  setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  if (!read_all(connection, length_bytes, sizeof(length_bytes)))
    goto done;
  length = ((uint32_t)length_bytes[0] << 24) |
           ((uint32_t)length_bytes[1] << 16) |
           ((uint32_t)length_bytes[2] << 8) |
           (uint32_t)length_bytes[3];
  if (length == 0 || length > PROMPT_LIMIT ||
      !read_all(connection, message, length))
    goto done;
  if (prompt_for_approval(message, length))
    decision = '1';
  resized = 1;
done:
  write_all(connection, &decision, 1);
  close(connection);
  if (resized)
    kill(-child, SIGWINCH);
}

static int relay(const char *socket_path, char *const command[])
{
  struct winsize window;
  struct termios raw_terminal;
  int listener;
  int master;
  int child_status = 0;
  pid_t child;
  bool stdin_open = true;
  bool master_open = true;
  bool child_reaped = false;

  if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO) ||
      tcgetattr(STDIN_FILENO, &saved_terminal) != 0 ||
      ioctl(STDIN_FILENO, TIOCGWINSZ, &window) != 0)
    return 64;
  listener = approval_listener(socket_path);
  if (listener < 0)
    return 64;
  child = forkpty(&master, NULL, &saved_terminal, &window);
  if (child < 0) {
    close(listener);
    unlink(socket_path);
    return 64;
  }
  if (child == 0) {
    close(listener);
    execvp(command[0], command);
    _exit(127);
  }
  raw_terminal = saved_terminal;
  cfmakeraw(&raw_terminal);
  if (tcsetattr(STDIN_FILENO, TCSANOW, &raw_terminal) != 0) {
    kill(-child, SIGTERM);
    waitpid(child, NULL, 0);
    close(master);
    close(listener);
    unlink(socket_path);
    return 64;
  }
  terminal_changed = true;
  atexit(restore_terminal);
  signal(SIGWINCH, on_resize);
  signal(SIGINT, on_terminate);
  signal(SIGTERM, on_terminate);
  signal(SIGHUP, on_terminate);
  signal(SIGPIPE, SIG_IGN);

  for (;;) {
    struct pollfd descriptors[3];
    nfds_t count = 0;
    int input_index = -1;
    int master_index = -1;
    int listener_index;
    unsigned char buffer[8192];
    ssize_t received;
    pid_t waited;

    if (terminating) {
      kill(-child, SIGTERM);
      break;
    }
    if (resized) {
      resized = 0;
      if (ioctl(STDIN_FILENO, TIOCGWINSZ, &window) == 0)
        ioctl(master, TIOCSWINSZ, &window);
      kill(-child, SIGWINCH);
    }
    if (stdin_open) {
      input_index = (int)count;
      descriptors[count++] = (struct pollfd){.fd = STDIN_FILENO, .events = POLLIN};
    }
    if (master_open) {
      master_index = (int)count;
      descriptors[count++] = (struct pollfd){.fd = master, .events = POLLIN};
    }
    listener_index = (int)count;
    descriptors[count++] = (struct pollfd){.fd = listener, .events = POLLIN};
    if (poll(descriptors, count, 100) < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (descriptors[listener_index].revents & POLLIN) {
      serve_approval(listener, child);
      continue;
    }
    if (input_index >= 0 && descriptors[input_index].revents & POLLIN) {
      received = read(STDIN_FILENO, buffer, sizeof(buffer));
      if (received <= 0)
        stdin_open = false;
      else if (!write_all(master, buffer, (size_t)received))
        master_open = false;
    }
    if (master_index >= 0 && descriptors[master_index].revents & POLLIN) {
      received = read(master, buffer, sizeof(buffer));
      if (received <= 0)
        master_open = false;
      else if (!write_all(STDOUT_FILENO, buffer, (size_t)received))
        break;
    }
    if (master_index >= 0 && (descriptors[master_index].revents & (POLLHUP | POLLERR)))
      master_open = false;
    waited = waitpid(child, &child_status, WNOHANG);
    if (waited == child) {
      child_reaped = true;
      break;
    }
    if (waited < 0 && errno != EINTR)
      break;
  }
  if (!child_reaped) {
    kill(-child, SIGTERM);
    waitpid(child, &child_status, 0);
  }
  close(master);
  close(listener);
  unlink(socket_path);
  restore_terminal();
  terminal_changed = false;
  if (terminating)
    return 128 + terminating;
  if (WIFEXITED(child_status))
    return WEXITSTATUS(child_status);
  if (WIFSIGNALED(child_status))
    return 128 + WTERMSIG(child_status);
  return 64;
}

int main(int argc, char **argv)
{
  if (argc < 4 || strcmp(argv[2], "--") != 0) {
    fprintf(stderr, "Usage: terminal-relay SOCKET -- COMMAND [ARGUMENT ...]\n");
    return 64;
  }
  return relay(argv[1], &argv[3]);
}
