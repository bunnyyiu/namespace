// Requires GNU extensions
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <uuid/uuid.h>
#include <stdio.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#define STACK_SIZE (1024 * 1024)
#define MAX_ARGV_SIZE 256
#define MAX_ENV_SIZE 256
#define MAX_VOL_COUNT 256
#define MAX_PATH_LENGTH 256
#define MAX_COMMAND_LENGTH 65536
#define UUID_LEN 37
#define MAX_COMMAND_ARG_LENGTH 128

char container_stack[STACK_SIZE];
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

char* hostname = "";

char* rootfs = "";

char* memory = "";

char* cpu_shares = "";

char* cpu_period = "";

char* cpu_quota = "";

char* container_args[MAX_ARGV_SIZE] = {NULL};

char *env[MAX_ENV_SIZE] = {NULL};

char *vol[MAX_VOL_COUNT] = {NULL};

int pipefd[2];

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
    char *target = strtok(NULL, ":");
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

void set_hostname(char *hostname) {
  sethostname(hostname, strlen(hostname));
}

int container_main(void* arg) {
  char ch;

  close(pipefd[1]);
  read(pipefd[0], &ch, 1);

  set_default_mount(rootfs);
  set_hostname(hostname);

  // unshare the host user namespace after mounting /dev
  unshare(CLONE_NEWUSER);
  //return execvpe(container_args[0], container_args, env);
  return execv(container_args[0], container_args);
}

int main(int argc, char ** argv) {
  int clone_flag = SIGCHLD;

  int option_index = 0;
  int i = 0;
  int envI = 0;
  int vI = 0;
  char* user;
  char* group;
  long int uid = 0;
  long int gid = 0;
  struct passwd *passwdResult;
  struct group *groupResult;

  while (1) {
    int c = getopt_long(argc, argv, short_options, long_options,
        &option_index);
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
        break;
      case 'm':
        memory = optarg;
        break;
      case 's':
        cpu_shares = optarg;
        break;
      case 'p':
        cpu_period = optarg;
        break;
      case 'q':
        cpu_quota = optarg;
        break;
      case 'u':
        user = strtok(optarg, ":");
        group = strtok(NULL, ":");
        uid = strtol(user, NULL, 10);
        gid = strtol(group, NULL, 10);

        if (uid == 0L) {
          // Search in /etc/passwd
          passwdResult = getpwnam(user);
          uid = passwdResult->pw_uid;
          if (gid == 0L) {
            if (group == "" ) {
              gid = passwdResult->pw_gid;
            } else {
              // Search in /etc/group
              groupResult = getgrnam(group);
              gid = groupResult->gr_gid;
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
  if (!rootfs) {
    rootfs = "./rootfs";
  }
  if (!hostname) {
    hostname = "container";
  }
  if (container_args[0] == NULL ) {
    container_args[0] = "/bin/bash";
    container_args[1] = NULL;
  }
  clone_flag = clone_flag | CLONE_NEWNS;
  clone_flag = clone_flag | CLONE_NEWPID;
  clone_flag = clone_flag | CLONE_NEWIPC;
  clone_flag = clone_flag | CLONE_NEWUTS;
  clone_flag = clone_flag | CLONE_NEWNET;

  pipe(pipefd);

  char uuid[37];
  generate_uuid(uuid);

  int container_pid = clone(container_main, container_stack + STACK_SIZE,
      clone_flag, NULL);
  set_uid_map(container_pid, (int) uid, getuid(), 1);
  set_gid_map(container_pid, (int) gid, getgid(), 1);

  int cgroupExitCode = set_cgroup("./cgroup.sh",uuid, container_pid,
      memory, cpu_shares, cpu_period, cpu_quota);
  if (cgroupExitCode != 0) {
    printf("Fail to set cgroup\n");
    return 1;
  }
  printf("Container PID : %d, UUID : %s\n", container_pid, uuid);

  close(pipefd[1]);

  waitpid(container_pid, NULL, 0);
  return 0;
}
