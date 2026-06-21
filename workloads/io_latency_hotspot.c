#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile sig_atomic_t keep_running = 1;

struct writer_args {
  int fd;
  useconds_t delay_us;
};

static void handle_signal(int signo) {
  (void)signo;
  keep_running = 0;
}

static void *writer_thread(void *arg) {
  struct writer_args *args = (struct writer_args *)arg;
  const char byte = 'x';

  while (keep_running) {
    usleep(args->delay_us);
    if (write(args->fd, &byte, 1) < 0 && errno != EINTR) {
      perror("write");
      keep_running = 0;
      break;
    }
  }

  return NULL;
}

static useconds_t parse_delay_us(int argc, char **argv) {
  char *end = NULL;
  long value = 2000;

  if (argc <= 1) {
    return (useconds_t)value;
  }

  errno = 0;
  value = strtol(argv[1], &end, 10);
  if (errno != 0 || end == argv[1] || *end != '\0' || value <= 0 || value > INT_MAX) {
    fprintf(stderr, "Usage: %s [writer_delay_us]\n", argv[0]);
    exit(2);
  }

  return (useconds_t)value;
}

int main(int argc, char **argv) {
  int pipe_fd[2];
  pthread_t writer;
  struct writer_args args;
  char byte;
  useconds_t delay_us = parse_delay_us(argc, argv);

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  if (pipe(pipe_fd) != 0) {
    perror("pipe");
    return 1;
  }

  args.fd = pipe_fd[1];
  args.delay_us = delay_us;
  if (pthread_create(&writer, NULL, writer_thread, &args) != 0) {
    perror("pthread_create");
    return 1;
  }

  printf("io_latency_hotspot started, pid=%d, writer_delay_us=%u\n", getpid(), (unsigned)delay_us);
  fflush(stdout);

  while (keep_running) {
    ssize_t nread = read(pipe_fd[0], &byte, 1);
    if (nread < 0 && errno != EINTR) {
      perror("read");
      keep_running = 0;
      break;
    }
  }

  pthread_join(writer, NULL);
  close(pipe_fd[0]);
  close(pipe_fd[1]);
  return 0;
}
