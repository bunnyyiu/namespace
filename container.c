#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <stdio.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#define STACK_SIZE (1024 * 1024)
#define MAX_ARGV_SIZE 256
#define MAX_ENV_SIZE 256
#define MAX_VOL_COUNT 256

char container_stack[STACK_SIZE];
const char* short_options = "f:h:c:e:v:";
const struct option long_options[] = {
  {"rootfs",  required_argument, NULL, 'f'},
  {"hostname", optional_argument, NULL, 'h'},
  {"command", optional_argument, NULL, 'c'},
  {"environment", optional_argument, NULL, 'e'},
  {"volume", optional_argument, NULL, 'v'},
  {0, 0, 0, 0 }
};

char* hostname;

char* rootfs;

char* container_args[MAX_ARGV_SIZE] = {NULL};

char *env[MAX_ENV_SIZE] = {NULL};

char *vol[MAX_VOL_COUNT] = {NULL};

int pipefd[2];

void set_map(char* file, int inside_id, int outside_id, int len) {
  FILE* mapfd = fopen(file, "w");
  if (NULL == mapfd) {
    perror("open file error");
    return;
  }
  fprintf(mapfd, "%d %d %d", inside_id, outside_id, len);
  fclose(mapfd);
}

void set_uid_map(pid_t pid, int inside_id, int outside_id, int len) {
  char file[256];
  sprintf(file, "/proc/%d/uid_map", pid);
  set_map(file, inside_id, outside_id, len);
}

void set_gid_map(pid_t pid, int inside_id, int outside_id, int len) {
  char file[256];
  sprintf(file, "/proc/%d/gid_map", pid);
  set_map(file, inside_id, outside_id, len);
}

void set_default_mount(char *rootfsPath) {
  char buf[65535];
  //remount "/proc" to make sure the "top" and "ps" show container's information
  snprintf(buf, sizeof(buf), "%s/%s", rootfsPath, "proc");
  if (mount("proc", buf, "proc", 0, NULL) != 0) {
    perror("proc");
  }
  snprintf(buf, sizeof(buf), "%s/%s", rootfsPath, "sys");
  if (mount("sysfs", buf, "sysfs", 0, NULL) != 0) {
    perror("sys");
  }
  snprintf(buf, sizeof(buf), "%s/%s", rootfsPath, "tmp");
  if (mount("none", buf, "tmpfs", 0, NULL) != 0) {
    perror("tmp");
  }
  snprintf(buf, sizeof(buf), "%s/%s", rootfsPath, "dev");
  if (mount("udev", buf, "devtmpfs", 0, NULL) != 0) {
    perror("dev");
  }
  snprintf(buf, sizeof(buf), "%s/%s", rootfsPath, "dev/pts");
  if (mount("devpts", buf, "devpts", 0, NULL) != 0) {
    perror("dev/pts");
  }
  snprintf(buf, sizeof(buf), "%s/%s", rootfsPath, "dev/shm");
  if (mount("shm", buf, "tmpfs", 0, NULL) != 0) {
    perror("dev/shm");
  }
  snprintf(buf, sizeof(buf), "%s/%s", rootfsPath, "run");
  if (mount("tmpfs", buf, "tmpfs", 0, NULL) != 0) {
    perror("run");
  }

  int vI = 0;
  while (vol[vI] != NULL) {
    char *src = strtok(vol[vI], ":");
    char *target = strtok(vol[vI], ":");
    snprintf(buf, sizeof(buf), "%s/%s", rootfsPath, target);
    if (mount(src, buf, "none", MS_BIND, NULL) != 0) {
      perror(vol[vI]);
    }
    vI++;
  }
  if (chdir(rootfsPath) != 0 || chroot("./") != 0 ){
    perror("chdir/chroot");
  }
}

void set_hostname(char *hostname) {
  sethostname(hostname, strlen(hostname));
}

int container_main(void* arg) {
  set_hostname(hostname);
  set_default_mount(rootfs);
  return execvpe(container_args[0], container_args, env);
}

int main(int argc, char **argv) {
  int clone_flag = SIGCHLD;

  int option_index = 0;
  int i = 0;
  int envI = 0;
  int vI = 0;

  while (1) {
    int c = getopt_long(argc, argv, short_options, long_options, &option_index);
    if (c == -1) {
      break;
    }
    switch (c) {
      case 'f':
        rootfs = optarg;
        break;
      case 'h':
        hostname = optarg;
        break;
      case 'c':
        container_args[i] = strtok(optarg," ");
        while(container_args[i] != NULL) {
          container_args[++i] = strtok(NULL," ");
        }
        break;
      case 'e':
        env[envI++] = optarg;
        env[envI] = NULL;
        break;
      case 'v':
        vol[vI++] = optarg;
        vol[vI] = NULL;
      case '?':
        break;
      default:
        printf("?? getopt returned character code 0%o ??\n", c);
        break;
    }
  }
  if (!rootfs) {
    rootfs = "./rootfs";
  }
  if (!hostname) {
    hostname = "container";
  }
  if (sizeof(container_args) == 0 ) {
    container_args[0] = "/bin/bash";
    container_args[1] = NULL;
  }
  clone_flag = clone_flag | CLONE_NEWNS;
  clone_flag = clone_flag | CLONE_NEWPID;
  clone_flag = clone_flag | CLONE_NEWIPC;
  clone_flag = clone_flag | CLONE_NEWUTS;
  clone_flag = clone_flag | CLONE_NEWNET;

  pipe(pipefd);

  int container_pid = clone(container_main, container_stack + STACK_SIZE,
      clone_flag, NULL);
  set_uid_map(container_pid, 0, getuid(), 1);
  set_gid_map(container_pid, 0, getgid(), 1);

  close(pipefd[1]);

  waitpid(container_pid, NULL, 0);
  return 0;
}
