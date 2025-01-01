#include "pwrules.h"
#include "pw_dir.h"
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sodium.h>
#include <sys/types.h>
#include <sys/stat.h>

#define PAGE_SIZE 0x1000
#define minkey "min_length"
#define maxkey "max_length"
#define nrkey "num_rules"
#define mrkey "min_rules"
#define rexkey "rules"
#define ckey "chars"
#define sitekey "site"
#define MAX_LINE 4096
#define MAX_SITES 32
#define MAX_SITE_LEN 255

/* helper function: find the key and value on a line of the form
 * "key" : "value"
 * return < 0 if no separator; key and value set to NULL if not quoted.
*/
int getkv(char *line, char** key, char **val) {
    char *kstr = strsep(&line,":");
    if (!line) return -1;
    *key = strchr(kstr,'"')+1;
    char *key_end = strrchr(kstr,'"');
    *key_end = 0;
    *val = strchr(line,'"');
    if (*val) {
	(*val)++;
        char *val_end = strrchr(*val,'"');
        *val_end = 0;
    }
    return 0;
}

/* helper function : is there a '}' in the string line */

int has_close_brace(char *line) {
    while (*line) {
        if (*line++ == '}') return 1;
    }
    return 0;
}


/* helper: read the regular expressions after the "rules" : { line in a pwgen json file. */

int parse_rexes(FILE *ffile, struct rule *f) {
    char nextline[MAX_LINE];
    int done = 0;
    char *key = NULL;
    char *val = NULL;
    char *rex = NULL;
    while(!done) {
        fgets(nextline,MAX_LINE,ffile);
        done = has_close_brace(nextline);
        if (getkv(nextline,&key,&val) == 0) {
            int idx = atoi(key);
            rex = aligned_alloc(PAGE_SIZE,PAGE_SIZE);
            strncpy(rex,val,MAX_LINE);
            /* mark the regex read-only to prevent race conditions */
            mprotect(rex,MAX_LINE,~PROT_WRITE & 0x7);
            f->rex[idx] = rex;
        }
    }
    return 0;
}

/* parse_pwgen_file(fname,filter): open json file "fname" and populate filter struct.
 * "permissive" in that:
 * + unexpected keys are ignored, 
 * + separating "," are not required,
 * + keys can be in any order within the file
 * + opening/closing curly braces can be omitted
 * + contents after the '}' are ignored.
 * returns < 0 if file cannot be opened, 0 otherwise.
*/

int parse_json_file(char *fname) {
    char nextline[MAX_LINE];
    char sitelist[MAX_SITES][MAX_SITE_LEN];
    int num_sites = 0;
    struct rule r;
    char *key = NULL;
    char *val = NULL;
    FILE *ff = fopen(fname,"r");
    if (!ff) return -1;
    int done = 0;
    int lstart = -1;
    while (!feof(ff) && !done) {
        lstart = ftell(ff); 
        fgets(nextline,MAX_LINE,ff);
        done = has_close_brace(nextline);
        if (getkv(nextline,&key,&val) == 0) {
            if (strcmp(key,minkey)==0) r.min_length = atoi(val);
            if (strcmp(key,maxkey)==0) r.max_length = atoi(val);
            if (strcmp(key,nrkey)==0) r.num_rex = atoi(val);
            if (strcmp(key,mrkey)==0) r.min_rex = atoi(val);
            if (strcmp(key,sitekey)==0) strcpy(sitelist[num_sites++],val);
            if (strcmp(key,ckey)==0) strcpy(r.charset,val);
            if (strcmp(key,rexkey)==0) {
                /* read to curly brace in case first rule is on the same line */
                fseek(ff,lstart,SEEK_SET);
                while (fgetc(ff) != '{');
                if (parse_rexes(ff,&r) < 0) return -1;
            }
        }
    }
    fclose(ff);
    for(int i = 0; i < num_sites; i++) {
        done = (write_pwr_file(sitelist[i],&r)==0) && done;
    }
    return done ? 0 : -1;
}

int get_pwr_filename(char *site, char *fn_out) {
    if (!site || !fn_out) return -1;
    unsigned char sitehash[crypto_hash_BYTES] = {0};
    long slen = strnlen(site,MAX_SITE_LEN);
    crypto_hash(sitehash,site,slen);
    get_rule_dir(fn_out);
    // Turn the first 16 bytes of the hash into a hex string
    hexlify_into(fn_out,sitehash,16);
    strcat(fn_out,".pwr");
    return 0;
}

int write_pwr_file(char *site, struct rule *r) {
    if (!site || !r) return -1;
    char filename[MAX_PATH];
    get_pwr_filename(site, filename);

    // make constant size binary blob
    unsigned char pr_blob[MAX_REGEX_RULES*MAX_RULE_LEN+256+4*sizeof(int)]; 
    int bloblen = MAX_REGEX_RULES*MAX_RULE_LEN+256+4*sizeof(int);
    // current blob position
    unsigned char *cbp = pr_blob;
    memcpy(cbp,r->charset,256);
    cbp += 256;
    memcpy(cbp,&(r->min_length),sizeof(int));
    cbp += sizeof(int);
    memcpy(cbp,&(r->max_length),sizeof(int));
    cbp += sizeof(int);
    memcpy(cbp,&(r->num_rex),sizeof(int));
    cbp += sizeof(int);
    memcpy(cbp,&(r->min_rex),sizeof(int));
    cbp += sizeof(int);
    for(int i = 0; i < r->num_rex; i++) 
        memcpy(cbp+i*MAX_RULE_LEN,r->rex[i],MAX_RULE_LEN);

    // write blob
    int rfd = open(filename, O_WRONLY | O_CREAT, 0600);
    if (rfd < 0) return errno;
    int w = write(rfd,pr_blob,bloblen);
    int err = errno;
    close(rfd);
    return  (w < bloblen) ? err : 0;
}

int parse_pwr_file(char *site, struct rule *r_out) {
    if (!site || !r_out) return -1;
    char filename[MAX_PATH];
    get_pwr_filename(site,filename);
    // read binary blob
    int rfd = open(filename, O_RDONLY);
    if (rfd < 0) return errno;
    unsigned char pr_blob[MAX_REGEX_RULES*MAX_RULE_LEN+256+4*sizeof(int)]; 
    int bloblen = MAX_REGEX_RULES*MAX_RULE_LEN+256+4*sizeof(int);
    if (read(rfd,pr_blob,bloblen) != bloblen) {
        close(rfd);
        return errno;
    }
    close(rfd);

    // read fields out of blob
    unsigned char* cbp = pr_blob;
    memcpy(r_out->charset,cbp,256);
    cbp += 256;
    memcpy(&(r_out->min_length),cbp,sizeof(int));
    cbp += sizeof(int);
    memcpy(&(r_out->max_length),cbp,sizeof(int));
    cbp += sizeof(int);
    memcpy(&(r_out->num_rex),cbp,sizeof(int));
    cbp += sizeof(int);
    memcpy(&(r_out->min_rex),cbp,sizeof(int));
    cbp += sizeof(int);
    for(int i = 0; i < r_out->num_rex; i++) {
        unsigned char* rex = calloc(MAX_RULE_LEN,1);
        if (!rex) return errno;
        memcpy(rex,cbp,MAX_RULE_LEN);
        cbp += MAX_RULE_LEN;
        r_out->rex[i] = rex;
    }
    return 0;
}

int get_site_json_file(char *site) {
    // cd to rule directory and cleanup last call
    if (!site) return -1;
    char bcpwm_path[PATH_MAX];
    get_bcpwm_dir(bcpwm_path);
    if (chdir(bcpwm_path) < 0) return -2;
    if ((unlink("bcpwm_rule.json") < 0) && (errno != ENOENT)) return -3;
    // download json file from site
    char cmdstring[PATH_MAX] = {0};
    sprintf(cmdstring, "wget -q -T 2 -t 2 --ca-certificate={/etc/bci/bci-cert/bcpwm.pem} https://%s/bcpwm_rule.json", site);
    if (system(cmdstring) > 0) return -4;
    // parse the downloaded file
    if (parse_json_file("bcpwm_rule.json") < 0) return -5;
    // Make sure we got a .pwr file for site out the deal!
    get_pwr_filename(site,bcpwm_path);
    struct stat fs;
    return stat(bcpwm_path, &fs);
}

int get_cloud_pwr_file(char *site) {
    char cmdstring[PATH_MAX] = {0};
    char rdir[PATH_MAX] = {0};
    get_rule_dir(rdir);
    unsigned char sitehash[crypto_hash_BYTES] = {0};
    long slen = strnlen(site,MAX_SITE_LEN);
    crypto_hash(sitehash,site,slen);
    sprintf(cmdstring, "cd %s ; wget -q -T 2 --ca-certificate={/etc/bci/bci-cert/bcpwm.pem} --no-proxy %s/get_rule/", rdir, get_cloud_base_url());
    hexlify_into(cmdstring,sitehash,16);
    strcat(cmdstring,".pwr");
    return -system(cmdstring);
}
