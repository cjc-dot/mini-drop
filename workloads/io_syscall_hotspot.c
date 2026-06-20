#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
  char buffer[4096];
  memset(buffer, 'A', sizeof(buffer));

  int fd = open("/tmp/mini-drop-io-syscall-hotspot.data", O_CREAT | O_RDWR | O_TRUNC, 0644);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  printf("io_syscall_hotspot started, pid=%d\n", getpid());
  fflush(stdout);

  while (1) {
    if (write(fd, buffer, sizeof(buffer)) < 0) {
      perror("write");
      close(fd);
      return 1;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
      perror("lseek");
      close(fd);
      return 1;
    }
    if (read(fd, buffer, sizeof(buffer)) < 0) {
      perror("read");
      close(fd);
      return 1;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
      perror("lseek");
      close(fd);
      return 1;
    }
    usleep(1000);
  }
}
