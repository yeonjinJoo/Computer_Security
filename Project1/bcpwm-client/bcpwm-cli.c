#include "pwfile.h"
#include "pw_dir.h"
#include "pwgen.h"
#include "controller.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#define MAX_PATH 4096
#define PAGE_SIZE 0x1000


void print_usage() {
    printf("bcpwm-cli : command-line interface for bcpwm. Usage:\n");
    printf("bcpwm-cli -i [masterpass [email]]\t (interactive mode)\n");
    printf("bcpwm-cli -l masterpass\t List available passwords\n");
    printf("bcpwm-cli -p masterpass site\t Retrieve password for site\n");
    printf("bcpwm-cli -a rfile.json\t Add site rules from rfile.json\n");
    printf("bcpwm-cli -s masterpass email\t sync database with cloud\n");
    printf("bcpwm-cli -g masterpass site\t Generate and save new password for site\n");
    printf("bcpwm-cli -r masterpass email\t Register email for cloud sync\n");
    printf("bcpwm-cli -c masterpass email token\t Complete cloud registration\n");
    printf("Setting masterpass to - triggers secure terminal entry of master passphrase.\n");
    exit(1);
}

int main(int argc, char **argv) {
    pwdb *pwds = NULL;
    char username[256];
    char master_pw[MAX_PW_LEN];
    if (argc < 2 || argv[1][0] != '-' || strlen(argv[1]) != 2) print_usage();
    if (bcpwm_initialize() < 0) {
        fprintf(stderr, "ERROR: Could not find or create bcpwm folder.\n");
    }
    init_db(&pwds);
    char cmd = argv[1][1];
    if (cmd == 'a') {
        if (argc == 3) {
            return add_rules_from_file(argv[2],0);
        } else {
            return -1;
        }
    }
    int spw = (cmd == 'i' && argc==2) || (argc>2 && strcmp(argv[2],"-") == 0);
    if (spw) {
        if (secure_read_password(master_pw,(cmd=='i')) < 0) exit(1);
    } else {
        strcpy(master_pw,argv[2]);
        if (set_encryption_password(master_pw) < 0) exit(1);
    }
    seed_rand();
    if(read_password_file(&pwds) < 0) {
        fprintf(stderr, "Error reading password file.  Incorrect password?\n");
        return -1;
    }
    switch(cmd) {
        case 'i':
            if (argc <= 3) return interact_loop(pwds,1);
            if (argc == 4) {
                set_account(argv[3]);
                return interact_loop(pwds,0);
            } else {
                print_usage();
            }
            break;
        case 'l':
            if (argc == 3) return list_passwords(pwds,0);
            print_usage();
            break;
        case 'p':
            if (argc == 4) return get_password(pwds,argv[3],0);
            print_usage();
            break;
        case 's':
            if (argc==4) {
                set_account(argv[3]);
                return sync_with_cloud(pwds,0);
            }
            print_usage();
            break;
        case 'g':
            if (argc == 4) return generate_password(pwds,argv[3],0);
            print_usage();
            break;
        case 'r':
            if (argc==4) return register_email(argv[3],0);
            print_usage();
            break;
        case 'c':
            if (argc==5) return confirm_registration(argv[3],argv[4],0);
            print_usage();
            break;
        default:
            print_usage();
            break;
    }
    return 0;
}

