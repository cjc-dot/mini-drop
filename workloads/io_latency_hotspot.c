#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile sig_atomic_t keep_running = 1;

struct writer_args {
  int fd;
};

static void handle_signal(int signo) {
  (void)signo;
  keep_running = 0;
}

static void *writer_thread(void *arg) {
  struct writer_args *args = (struct writer_args *)arg;
  const char byte = 'x';

  while (keep_running) {
    usleep(2000);
    if (write(args->fd, &byte, 1) < 0 && errno != EINTR) {
      perror("write");
      keep_running = 0;
      break;
    }
  }

  return NULL;
}

int main(void) {
  int pipe_fd[2];
  pthread_t writer;
  struct writer_args args;
  char byte;

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  if (pipe(pipe_fd) != 0) {
    perror("pipe");
    return 1;
  }

  args.fd = pipe_fd[1];
  if (pthread_create(&writer, NULL, writer_thread, &args) != 0) {
    perror("pthread_create");
    return 1;
  }

  printf("io_latency_hotspot started, pid=%d\n", getpid());
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
