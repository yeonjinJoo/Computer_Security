#include "pw_dir.h"
#include "pwfile.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <limits.h>
#include <sodium.h>
#include <unistd.h>
#include <stdlib.h>

// Let's just agree that 127 chars is long enough for your email.
char account[128] = {0};
char* upsync_url = "https://bcpwm.badlycoded.net:453/sync_up";
char* downsync_url = "https://bcpwm.badlycoded.net:453/sync_down";
char* register_url = "https://bcpwm.badlycoded.net:453/init_client";
char* confirm_url = "https://bcpwm.badlycoded.net:453/confirm-client";

char *get_cloud_base_url() {
    return "https://bcpwm.badlycoded.net:453/";
}

char *hexlify[] = {
  "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F", 
  "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B", "1C", "1D", "1E", "1F", 
  "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F", 
  "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B", "3C", "3D", "3E", "3F", 
  "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F", 
  "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F", 
  "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F", 
  "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7A", "7B", "7C", "7D", "7E", "7F", 
  "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F", 
  "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B", "9C", "9D", "9E", "9F", 
  "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF", 
  "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF", 
  "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF", 
  "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF", 
  "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF", 
  "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF"  
};

void hexlify_into(char *dst, const unsigned char *src, int len) {
    const unsigned char *p = src;
    for (; (p-src) < len || (len < 0 && *p); p++) strcat(dst,hexlify[*p]);
}

/* NOTE: eventually this will need some macros to be cross-platfrom */
int get_bcpwm_dir(char *fn_out) {
    char *hdir = getenv("HOME");
    if (!hdir) return -1;
    sprintf(fn_out, "%s/.bcpwm/", hdir);
    return 0;
}

int get_pw_dir(char *fn_out) {
    get_bcpwm_dir(fn_out);
    strcat(fn_out,"pwdb/");
    return 0;
} 

int get_rule_dir(char *fn_out) {
    get_bcpwm_dir(fn_out);
    strcat(fn_out,"pwrules/");
    return 0;
}

int set_account(char *email) {
    strncpy(account,email,127);
    account[127] = 0;
    return 0;
}

int sync_cloud(char *hacct, char *hexpass) {
    char bcpdir[PATH_MAX];
    get_bcpwm_dir(bcpdir);
    if (chdir(bcpdir) != 0) return -2;
    char cmdstring[PATH_MAX];
    sprintf(cmdstring, "tar cf %s.tar --warning=none pwdb pwrules", hacct);
    if (system(cmdstring) < 0) return -3;
    // eventually add --pinned-pubkey=
    sprintf(cmdstring, 
        "wget -q -T 2 --ca-certificate={/etc/bci/bci-cert/bcpwm.pem} --no-proxy --post-file=%s.tar %s/%s/%s",
        hacct,upsync_url,hacct,hexpass);
    if (system(cmdstring) < 0) return -4;
    sprintf(cmdstring, "%s.tar", hacct);
    if (remove(cmdstring) < 0) return -5;
    sprintf(cmdstring,
        "wget -q -T 2 --ca-certificate={/etc/bci/bci-cert/bcpwm.pem} --no-proxy %s/%s.tar",
        downsync_url,hacct);
    if (system(cmdstring) < 0) return -6;
    sprintf(cmdstring,
        "tar --warning=none --extract --keep-newer-files --file=%s.tar", hacct);
    if (system(cmdstring) < 0) return -7;
    sprintf(cmdstring, "%s.tar", hacct);
    if (remove(cmdstring) < 0) return -8; 
    return 0;
}

int sync_pwdb(pwdb *pwds) {
    if (write_password_file(pwds) < 0) return -1;
    char upw_hash[crypto_hash_BYTES] = {0};
    get_upload_password(upw_hash);
    char hexpass[17] = {0};
    hexlify_into(hexpass,upw_hash,8);
    char hacct[256] = {0};
    hexlify_into(hacct,account,-1);
    return sync_cloud(hacct,hexpass);
}

/* Note: bcpwm dir will always be directly under an existing dir */
/* (Unless the user's filesystem is borked) */
/* so no recursive directory constructon needed */
int mkdir_or_exists(char *path) {
    struct stat fs;
    if (mkdir(path,0700) < 0) {
        if (errno != EEXIST) return -1; /* what? */
        if (stat(path, &fs) < 0) return -2; /* FS error? */
        if (!S_ISDIR(fs.st_mode)) return -3; /* nondir exists with pathname */
    }
    /* OK, either we made the dir or it already existed! */
    return 0;   
}

int bcpwm_initialize(void) {
    char path[PATH_MAX];
    if (get_bcpwm_dir(path) < 0) return -1;
    if (mkdir_or_exists(path) < 0) return -2;
    if (get_pw_dir(path) < 0) return -3;
    if (mkdir_or_exists(path) < 0) return -4;
    if (get_rule_dir(path) < 0) return -5;
    if (mkdir_or_exists(path) < 0) return -6;
    return 0;
}

int register_account(char *email) {
    char cmdstring[PATH_MAX] = {0};
    char upw[crypto_hash_BYTES] = {0};
    get_upload_password(upw);
    sprintf(cmdstring, "wget -q --ca-certificate={/etc/bci/bci-cert/bcpwm.pem} --no-proxy -T 2 -t 2 %s/", register_url);
    hexlify_into(cmdstring,email,-1);
    strcat(cmdstring,"/");
    hexlify_into(cmdstring,upw,8);
    if (system(cmdstring) == 0) return 0;
    /* there was an error, was it because the email is already registered? */
    sprintf(cmdstring, "wget -q -S --ca-certificate={/etc/bci/bci-cert/bcpwm.pem} --no-proxy -T 2 -t 2 %s/", register_url);
    hexlify_into(cmdstring,email,-1);
    strcat(cmdstring,"/");
    hexlify_into(cmdstring,upw,8);
    strcat(cmdstring, " | grep -q 409");
    if (system(cmdstring) == 0) return -1;
    return -2;
}
const char *get_account() {
    return account;
}
int complete_registration(const char *email, char *token) {
    char cmdstring[PATH_MAX] = {0};
    char upw[crypto_hash_BYTES] = {0};
    get_upload_password(upw);
    sprintf(cmdstring, "wget -q --ca-certificate={/etc/bci/bci-cert/bcpwm.pem} --no-proxy -T 2 -t 2 %s/", confirm_url);
    hexlify_into(cmdstring,email,-1);
    strcat(cmdstring,"/");
    hexlify_into(cmdstring,upw,8);
    strcat(cmdstring,"/");
    strcat(cmdstring,token);
    return -system(cmdstring);
}
