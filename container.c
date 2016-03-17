// Requires GNU extensions
#define _GNU_SOURCE

#include <sys/wait.h>
#include <sys/mount.h>
#include <uuid/uuid.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>

#define STACK_SIZE (1024 * 1024)
#define MAX_ARGV_SIZE 256
#define MAX_ENV_SIZE 256
#define MAX_VOL_COUNT 256
#define MAX_PATH_LENGTH 256
#define MAX_COMMAND_LENGTH 65536
#define UUID_LENGTH 37
#define MAX_COMMAND_ARG_LENGTH 128

const char* short_options = "f:h:c:e:v:u:m:s:p:q:";
const struct option long_options[] = {
  {"rootfs",  required_argument, NULL, 'f'},
  {"hostname", required_argument, NULL, 'h'},
  {"command", required_argument, NULL, 'c'},
  {"environment", required_argument, NULL, 'e'},
  {"volume", required_argument, NULL, 'v'},
  {"user", required_argument, NULL, 'u'},
  {"memory", required_argument, NULL, 'm'},
  {"cpu_shares", required_argument, NULL, 's'},
  {"cpu_period", required_argument, NULL, 'p'},
  {"cpu_quota", required_argument, NULL, 'q'},
  {0, 0, 0, 0 }
};

int pipefd[2];

struct Config {
  char* hostname;
  char* rootfs;
  char* memory;
  char* cpu_shares;
  char* cpu_period;
  char* cpu_quota;
  char* container_args[MAX_ARGV_SIZE];
  char* environment[MAX_ENV_SIZE];
  char* volume[MAX_VOL_COUNT];
  char uuid[UUID_LENGTH];
  long int uid;
  long int gid;
} config;

void generate_uuid(char* uuid) {
  uuid_t out;
  uuid_generate(out);
  uuid_unparse(out, uuid);
}

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
  char file[MAX_PATH_LENGTH];
  sprintf(file, "/proc/%d/uid_map", pid);
  set_map(file, inside_id, outside_id, len);
}

void set_gid_map(pid_t pid, int inside_id, int outside_id, int len) {
  char file[MAX_PATH_LENGTH];
  sprintf(file, "/proc/%d/gid_map", pid);
  set_map(file, inside_id, outside_id, len);
}

void set_default_mount(char *rootfsPath) {
  char buf[MAX_PATH_LENGTH];
  //remount "/proc" to make sure the "top" and "ps" show container's information
  snprintf(buf, MAX_PATH_LENGTH, "%s/%s", rootfsPath, "proc");
  if (mount("proc", buf, "proc", 0, NULL) != 0) {
    perror("proc");
  }
  snprintf(buf, MAX_PATH_LENGTH, "%s/%s", rootfsPath, "sys");
  if (mount("sysfs", buf, "sysfs", 0, NULL) != 0) {
    perror("sys");
  }
  snprintf(buf, MAX_PATH_LENGTH, "%s/%s", rootfsPath, "tmp");
  if (mount("none", buf, "tmpfs", 0, NULL) != 0) {
    perror("tmp");
  }
  snprintf(buf, MAX_PATH_LENGTH, "%s/%s", rootfsPath, "dev");
  if (mount("udev", buf, "devtmpfs", 0, NULL) != 0) {
    perror("dev");
  }
  snprintf(buf, MAX_PATH_LENGTH, "%s/%s", rootfsPath, "dev/pts");
  if (mount("devpts", buf, "devpts", 0, NULL) != 0) {
    perror("dev/pts");
  }
  snprintf(buf, MAX_PATH_LENGTH, "%s/%s", rootfsPath, "dev/shm");
  if (mount("shm", buf, "tmpfs", 0, NULL) != 0) {
    perror("dev/shm");
  }
  snprintf(buf, MAX_PATH_LENGTH, "%s/%s", rootfsPath, "run");
  if (mount("tmpfs", buf, "tmpfs", 0, NULL) != 0) {
    perror("run");
  }

  int volI = 0;
  while (config.volume[volI] != NULL) {
    char *src = strtok(config.volume[volI], ":");
    char *target = strtok(NULL, ":");
    snprintf(buf, MAX_PATH_LENGTH, "%s/%s", rootfsPath, target);
    if (mount(src, buf, "none", MS_BIND, NULL) != 0) {
      perror(config.volume[volI]);
    }
    volI++;
  }
  if (chdir(rootfsPath) != 0 || chroot("./") != 0 ){
    perror("chdir/chroot");
  }
}

int set_cgroup(char* cgroupScript, char* uuid,int pid, char* memory,
    char* cpu_shares, char* cpu_period, char* cpu_quota) {
  char command[MAX_COMMAND_LENGTH];
  snprintf(command, MAX_COMMAND_LENGTH, "%s %s %d", cgroupScript, uuid, pid);

  char buf[MAX_COMMAND_LENGTH];
  if (strcmp("", memory) != 0) {
    snprintf(buf, MAX_COMMAND_LENGTH, " -m %s", memory);
    strncat(command, buf, MAX_COMMAND_ARG_LENGTH);
  }
  if (strcmp("", cpu_shares) != 0) {
    snprintf(buf, MAX_COMMAND_LENGTH, " -s %s", cpu_shares);
    strncat(command, buf, MAX_COMMAND_ARG_LENGTH);
  }
  if (strcmp("", cpu_period) != 0) {
    snprintf(buf, MAX_COMMAND_LENGTH, " -p %s", cpu_period);
    strncat(command, buf, MAX_COMMAND_ARG_LENGTH);
  }
  if (strcmp("", cpu_quota) != 0) {
    snprintf(buf, MAX_COMMAND_LENGTH, " -q %s", cpu_quota);
    strncat(command, buf, MAX_COMMAND_ARG_LENGTH);
  }
  return system(command);
}

void set_hostname(char* hostname) {
  sethostname(hostname, strlen(hostname));
}

int container_main(void* arg) {
  char ch;

  close(pipefd[1]);
  read(pipefd[0], &ch, 1);

  set_default_mount(config.rootfs);
  set_hostname(config.hostname);

  // unshare the host user namespace after mounting /dev
  unshare(CLONE_NEWUSER);
  return execvpe(config.container_args[0], config.container_args,
      config.environment);
}

void init_default_values() {
  config.hostname = "";
  config.rootfs = "";
  config.memory = "";
  config.cpu_shares = "";
  config.cpu_period = "";
  config.cpu_quota = "";
  config.container_args[0] = NULL;
  config.environment[0] = NULL;
  config.volume[0] = NULL;
  config.uid = 0;
  config.gid = 0;
}

int main(int argc, char* argv[]) {
  int clone_flag = SIGCHLD;
  int i = 0;
  int envI = 0;
  int volI = 0;
  char* user;
  char* group;
  struct passwd* passwdResult;
  struct group* groupResult;

  init_default_values();

  int option_index = 0;
  while (1) {
    int c = getopt_long(argc, argv, short_options, long_options,
        &option_index);
    if (c == -1) {
      break;
    }
    switch (c) {
      case 'f':
        config.rootfs = optarg;
        break;
      case 'h':
        config.hostname = optarg;
        break;
      case 'c':
        config.container_args[i] = strtok(optarg," ");
        while(config.container_args[i] != NULL) {
          config.container_args[++i] = strtok(NULL," ");
        }
        break;
      case 'e':
        config.environment[envI] = optarg;
        config.environment[++envI] = NULL;
        break;
      case 'v':
        config.volume[volI] = optarg;
        config.volume[++volI] = NULL;
        break;
      case 'm':
        config.memory = optarg;
        break;
      case 's':
        config.cpu_shares = optarg;
        break;
      case 'p':
        config.cpu_period = optarg;
        break;
      case 'q':
        config.cpu_quota = optarg;
        break;
      case 'u':
        user = strtok(optarg, ":");
        group = strtok(NULL, ":");
        config.uid = strtol(user, NULL, 10);
        config.gid = strtol(group, NULL, 10);

        if (config.uid == 0L) {
          // Search in /etc/passwd
          passwdResult = getpwnam(user);
          config.uid = passwdResult->pw_uid;
          if (config.gid == 0L) {
            if (strcmp("", group)) {
              config.gid = passwdResult->pw_gid;
            } else {
              // Search in /etc/group
              groupResult = getgrnam(group);
              config.gid = groupResult->gr_gid;
            }
          }
        }
        break;
      case '?':
        break;
      default:
        break;
    }
  }
  if (strcmp("", config.rootfs)) {
    config.rootfs = "./rootfs";
  }
  if (strcmp("", config.hostname)) {
    config.hostname = "container";
  }
  if (config.container_args[0] == NULL ) {
    config.container_args[0] = "/bin/bash";
    config.container_args[1] = NULL;
  }
  clone_flag = clone_flag | CLONE_NEWNS;
  clone_flag = clone_flag | CLONE_NEWPID;
  clone_flag = clone_flag | CLONE_NEWIPC;
  clone_flag = clone_flag | CLONE_NEWUTS;
  clone_flag = clone_flag | CLONE_NEWNET;

  pipe(pipefd);

  generate_uuid(config.uuid);

  char container_stack[STACK_SIZE];
  int container_pid = clone(container_main, container_stack + STACK_SIZE,
      clone_flag, NULL);
  set_uid_map(container_pid, (int) config.uid, getuid(), 1);
  set_gid_map(container_pid, (int) config.gid, getgid(), 1);

  int cgroupExitCode = set_cgroup("./cgroup.sh",config.uuid, container_pid,
      config.memory, config.cpu_shares, config.cpu_period, config.cpu_quota);
  if (cgroupExitCode != 0) {
    printf("Fail to set cgroup\n");
    return 1;
  }
  printf("Container PID : %d, UUID : %s\n", container_pid, config.uuid);

  close(pipefd[1]);

  waitpid(container_pid, NULL, 0);
  return 0;
}
