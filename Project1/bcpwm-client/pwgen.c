#include "pwgen.h"
#include <sodium.h>
#include "pwrules.h"
#include "pw_dir.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#define MAX_PATH 4096
#define MAX_PW_LEN 32

unsigned char rng_state[crypto_hash_BYTES];
char default_charset[] = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@$./`~^";
char* default_rex[] = {
    "[[:alpha:]]",
    "[[:upper:]]",
    "[[:digit:]]",
    "[[:punct:]]"
};

void seed_rand() {
    int r = open("/dev/random", O_RDONLY);
    read(r,rng_state,crypto_hash_BYTES);
    close(r);
}

/* mix in some randomness to (already random) current state with current system time */
void reseed_rand() {
    unsigned char curr_time[sizeof(time_t)];
    time((time_t *)curr_time);
    for(int i = 0; i < crypto_hash_BYTES; i++)
        rng_state[i] ^= (rng_state[i] ^ curr_time[i % sizeof(time_t)]);
}

/* take the first sizeof(long) bytes from the state, hash state to get next state */
unsigned long next_rand() {
    unsigned long result;
    memcpy(&result,rng_state,sizeof(long));
    unsigned char last_state[crypto_hash_BYTES];
    memcpy(last_state,rng_state,crypto_hash_BYTES);
    crypto_hash(rng_state,last_state,crypto_hash_BYTES);
    return result;
}

int gen_password(char *site, char *pw_out) {
    struct rule pwf;
    int using_default = 0;
    char fname[MAX_PATH] = {0};
    get_pwr_filename(site,fname);
    /* check if .pwr file is installed in current directory: */
    struct stat fs;
    if (stat(fname,&fs) < 0) {
        /* .pwr file doesn't exist, try grabbing from site */
        if (get_site_json_file(site) < 0) {
            /* failed to get json file from site, try cloud */
            if (get_cloud_pwr_file(site) < 0) { 
                /* not on the cloud either, so set default rule  */
                using_default = 1;
                pwf.min_length = 10;
                pwf.max_length = 11;
                pwf.num_rex = 4;
                pwf.min_rex = 3;
                strcpy(pwf.charset, default_charset);
                pwf.rex[0] = default_rex[0];
                pwf.rex[1] = default_rex[1];
                pwf.rex[2] = default_rex[2];
                pwf.rex[3] = default_rex[3];
            }
        }
    }
    if (!using_default && parse_pwr_file(site,&pwf) < 0) return -2; 

    reseed_rand();

    int rpass = 0;
    do {
        rpass = 0;
        memset(pw_out,0,MAX_PW_LEN);
        /* pick a length randomly between pwf.min_length and pwf.max_length */
        int pw_len = pwf.min_length + (next_rand() % (pwf.max_length - pwf.min_length));

        /* fill with randomly chosen chars from allowable chars */
        int clen = strlen(pwf.charset);
        for (int i = 0; i < pw_len; i++) {
            pw_out[i] = pwf.charset[next_rand() % clen];
        }

        /* check against regexes; stop once we hit min number to pass */
        for (int i = 0; i < pwf.num_rex && rpass < pwf.min_rex; i++) {
            char gcmd[MAX_PATH];
            sprintf(gcmd,"grep -q '%s'",pwf.rex[i]);
            FILE *grep = popen(gcmd,"w");
            fprintf(grep,pw_out);
            if (pclose(grep) == 0) rpass++;
        }
    } while (rpass < pwf.min_rex);
    return 0;
}
