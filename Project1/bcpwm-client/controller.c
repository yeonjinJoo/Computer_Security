/* controller.c -- "drive" by reading/responding to requests */
#include "controller.h"
#include "pwgen.h"
#include "pwrules.h"
#include "pwfile.h"
#include "pw_dir.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#define MAX_PW_LEN 32
#define MAX_PATH 4096

void trim(char *s) {
    s[strcspn(s,"\n")]=0;
}

int secure_read_password(char *pw_out, int interactive) {
    if (interactive) {
        printf("Enter master passphrase: ");
    }
    int is_tty = 1;
    struct termios term;
    if (tcgetattr(fileno(stdin), &term) < 0) {
        if (errno == ENOTTY) is_tty = 0;
        else {
            if (interactive) 
                fprintf(stderr, "Could not access the terminal configuration! Exiting...\n");
            return -1;
        }
    }

    term.c_lflag &= ~ECHO;
    if (is_tty && (tcsetattr(fileno(stdin), 0, &term) < 0)) {
        if (interactive) fprintf(stderr,"Could not turn echoing off! Exiting...\n");
        return -1;
    }

    fgets(pw_out, MAX_PW_LEN, stdin);
    trim(pw_out);
    term.c_lflag |= ECHO;
    if (is_tty && (tcsetattr(fileno(stdin), 0, &term) < 0)) {
        if (interactive) fprintf(stderr, "Could not re-enable echo! Exiting...\n");
        return -1;
    }

    if (set_encryption_password(pw_out) < 0) {
        if (interactive) fprintf(stderr, "ERROR: Failed to set master passphrase!\n");
        return -1;
    }
    return 0;
}

int list_passwords(pwdb *pwds, int i) {
    site_list *ls = list_sites(pwds);
    site_list *curr = ls;
    while (curr != NULL) {
        printf("%s%s\n", i ? "\t" : "", curr->site);
        curr = curr->next;
    }
    while (ls != NULL) {
        curr = ls;
        ls = ls -> next;
        free(curr);
    }
    return 0;
}
int get_password(pwdb *pwds, char* site, int interactive) {
    char password[MAX_PW_LEN];
    if (get_site_password(pwds,site,password) < 0) {
        if (interactive) fprintf(stderr, "No password found for site <%s>\n", site);
        return -1;
    }
    if (interactive) printf("Password for <%s>: ",site);
    printf("%s\n",password);
    return 0;
}

int add_rules_from_file(char *filename, int interactive) {
    int status = parse_json_file(filename);
    if (interactive) {
        if (status == 0) printf("Rules added!\n");
        else fprintf(stderr, "ERROR: could not read and install rules file '%s'.\n", filename);
    }
    return status;
}

int sync_with_cloud(pwdb *pwds, int interactive) {
    if (interactive) printf("Syncing with cloud!\n");
    if (sync_pwdb(pwds) < 0) {
        if (interactive) fprintf(stderr, "Sync failed! Maybe try again later?\n");
        return -1;
    }
    if (interactive) printf("Success!\n");
    return 0;
}

int register_email(char *email, int interactive) {
    set_account(email);
    if (interactive) printf("Attempting to initiate email registration...\n");
    int res = register_account(email);
    if (res == 0) {
        if (interactive) 
            printf("Registration sent! Click confirmation URL in email or select \'(C)onfirm registration\' and use emailed code to complete process.\n");
        return 0;
    }
    if (res == -1 && interactive) 
        printf("Your email address has already been registered.\n");
    if (res == -2 && interactive) 
        fprintf(stderr, "Encountered an error and could not complete registration...\n");
    return res;
}

int confirm_registration(const char *email, char *token, int interactive) {
    if (complete_registration(email,token) < 0) {
        if (interactive) fprintf(stderr,"There was an error and the operation could not be completed.\n");
        return -1;
    }
    if (interactive) printf("Confirmation Confirmed.\n");
    return 0;
}

int generate_password(pwdb *pwds, char *site, int interactive) {
    char password[MAX_PW_LEN] = {0};
    if (interactive) {
        printf("Generating a password for site <%s>...\n",site);
    }
    reseed_rand();
    if (gen_password(site,password) < 0) {
        if (interactive) 
            fprintf(stderr, "Encountered an error and could not generate a password.\n");
        return -1;
    } 
    if (interactive) printf("New password: ");
    printf("%s\n",password);
    if (set_site_password(pwds,site,password) < 0) {
        if (interactive) 
            fprintf(stderr, "!!Error setting new password in memory.");
        return -2;
    }
    if (write_password_file(pwds) < 0) {
        if (interactive)
            fprintf(stderr, "!!Error saving new password.\n");
        return -3;
    }
    return 0;
}


void print_options() {
    printf("\nSelect one of the following options:\n");
    printf("(L)ist passwords.\n");
    printf("(P)rint password.\n");
    printf("(G)enerate password.\n");
    printf("(S)ync to cloud.\n");
    printf("(R)egister email account.\n");
    printf("(C)onfirm registration.\n");
    printf("(A)dd site rules from file.\n");
    printf("(Q)uit.\n");
    printf(">");
}

int interact_loop(pwdb *pwds, int local) {
    if (local) printf("Starting in local-only mode, no email set.\n\n");
    char site[MAX_SITE_LEN];
    char email[MAX_SITE_LEN];
    char code[MAX_PW_LEN];
    char rfile[PATH_MAX];
    char choice;
    while (!feof(stdin)) {
        printf("Press <ENTER> to continue:");
        getchar();
        print_options();
        choice = getchar();
        if (getchar() != '\n') continue;
        switch(toupper(choice)) {
            case 'L':
                list_passwords(pwds,1);
                break;
            case 'P':
                printf("\nEnter site: ");
                fgets(site,MAX_SITE_LEN,stdin);
                trim(site);
                get_password(pwds,site,1);
                break;
            case 'G':
                printf("\nEnter site: ");
                fgets(site,MAX_SITE_LEN,stdin);
                trim(site);
                generate_password(pwds,site,1);
                break;
            case 'S':
                if (local) {
                    printf("\nNot available in local mode!\n");
                } else {
                    sync_with_cloud(pwds,1);
                    init_db(&pwds);
                    if (read_password_file(&pwds) < 0)
                        fprintf(stderr, "ERROR: Failed to reload after sync.\n");
                }
                break;
            case 'R':
                printf("\nEnter email address to register: ");
                fgets(email,MAX_SITE_LEN,stdin);
                trim(email);
                register_email(email,1);
                local=0;
                break;
            case 'C':
                if (local) {
                    printf("\nMust register an address first!\n");
                    continue;
                }
                printf("\nEnter e-mailed confirmation code: ");
                fgets(code,MAX_PW_LEN,stdin);
                trim(code);
                confirm_registration(get_account(),code,1);
                break;
            case 'A':
                printf("\nEnter file name: ");
                fgets(rfile,PATH_MAX,stdin);
                trim(rfile);
                add_rules_from_file(rfile,1);
                break;
            case 'Q':
                printf("\nOK, Goodbye!\n");
                return 0;
        }
    }
    return 0;
}