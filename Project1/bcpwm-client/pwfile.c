#include "pwfile.h"
#include "pw_dir.h"
#include <sodium.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <errno.h>
#include <glob.h>
#include <limits.h>

#define PAGE_SIZE 0x1000
#define PWHASH_IT_NUM 0x1

unsigned char *pwfile_key;

/* functions in this file
 * set_encryption_password(char *epwd)
 * read_pw_file(filename,pwdb_out)
 * list_sites(pwdb)
 * get_site_password(pwdb,site,pwout)
 * set_site_password(pwdb,site,password)
 * write_pw_file(filename,pwdb)
 */

int set_encryption_password(char *pwfile_pwd) {
    unsigned char hashbuffer[crypto_hash_BYTES];
    unsigned char keybuffer[crypto_secretbox_KEYBYTES];
    int plen = strlen(pwfile_pwd);
    for (int i = 0; i < sizeof(keybuffer); i++) 
        keybuffer[i] = pwfile_pwd[i % plen];
    for (int i = 0; i < PWHASH_IT_NUM; i++) {
        crypto_hash(hashbuffer,keybuffer,sizeof(keybuffer));
        memcpy(keybuffer,hashbuffer,sizeof(keybuffer));   
    }
    pwfile_key = aligned_alloc(PAGE_SIZE,PAGE_SIZE);
    if (!pwfile_key) return -1;
    memcpy(pwfile_key,keybuffer,crypto_secretbox_KEYBYTES);
    memset(hashbuffer, 0, sizeof(hashbuffer));
    memset(keybuffer, 0, sizeof(keybuffer));
    memset(pwfile_pwd, 0, plen);
    if (mlock(pwfile_key, PAGE_SIZE) < 0 || 
        mprotect(pwfile_key, crypto_secretbox_KEYBYTES, PROT_NONE) < 0) goto prot_fail;

    return 0;

  prot_fail:
    memset(pwfile_key, 0, crypto_secretbox_KEYBYTES);
    munlock(pwfile_key,PAGE_SIZE);
    free(pwfile_key);
    pwfile_key = NULL;
    return -2;
}

int get_upload_password(char *upw) {
    if (!upw) return -1;
    char to_hash[crypto_secretbox_KEYBYTES+16];
    strcpy(to_hash,"bcpwmuploadkey||");
    mprotect(pwfile_key, crypto_secretbox_KEYBYTES, PROT_READ);
    strncat(to_hash,pwfile_key,crypto_secretbox_KEYBYTES);
    crypto_hash(upw,to_hash,sizeof(to_hash));
    mprotect(pwfile_key, crypto_secretbox_KEYBYTES, PROT_NONE);
    return 0;
}
site_list *list_sites(pwdb *pwds) {
    if (!pwds) return NULL;
    site_list *result = NULL;
    while (pwds != NULL) {
        /*  make db entry readable */
        mprotect(pwds,sizeof(pwdb), PROT_READ);
        site_list *next_site = (site_list *)malloc(sizeof(site_list));
        strcpy(next_site->site,pwds->site);
        next_site->next = result;
        result = next_site;
        pwdb *next = pwds->next;
        /* remove read protection for db entry */
        mprotect(pwds, sizeof(pwdb), ~PROT_READ & 0x7);
        pwds = next;
    }
    return result;
}

int get_site_password(pwdb *pwds, char *site, char *pw_out) {
    if (!pwds) return -1;
    while (pwds != NULL) {
        mprotect(pwds, sizeof(pwdb), PROT_READ);
        if (strncmp(site,pwds->site,MAX_SITE_LEN)==0) {
            strncpy(pw_out,pwds->pwd,MAX_PW_LEN);
            mprotect(pwds,sizeof(pwdb), ~PROT_READ & 0x7);
            return 0;
        }
        pwdb *next = pwds->next;
        mprotect(pwds, sizeof(pwdb), ~PROT_READ & 0x7);
        pwds = next;
    }
    return -1;
}

int set_site_password(pwdb *pwds, char *site, char *pwd) {
    if (!pwds) return -1;
    pwdb *last;
    while (pwds != NULL) {
        mprotect(pwds,sizeof(pwdb), PROT_READ);
        if (pwds->site[0] == 0 && pwds->pwd[0]==0) {
            mprotect(pwds,sizeof(pwdb), PROT_WRITE);
            strncpy(pwds->site,site,MAX_SITE_LEN);
        }
        if (strncmp(site,pwds->site,MAX_SITE_LEN) == 0) {
            mprotect(pwds,sizeof(pwdb), PROT_WRITE);
            pwds->changed = 1;
            strncpy(pwds->pwd,pwd,MAX_PW_LEN);
            /* unset read and write bits */
            mprotect(pwds,sizeof(pwdb), ~PROT_WRITE & 0x7);
            mprotect(pwds,sizeof(pwdb), ~PROT_READ & 0x7);
            return 0;
        }
        last = pwds;
        pwds = pwds->next;
        mprotect(last,sizeof(pwdb), ~PROT_READ & 0x7);
    }
    /* made it to end, allocate new entry */
    pwdb *new = (pwdb *)aligned_alloc(PAGE_SIZE, PAGE_SIZE);
    if (!new) return errno;
    if (mlock(new,PAGE_SIZE) < 0) return errno;
    strncpy(new->site,site,MAX_SITE_LEN);
    strncpy(new->pwd,pwd,MAX_PW_LEN);
    new->changed=1;
    new->next = NULL;
    mprotect(last,sizeof(pwdb), PROT_WRITE);
    last->next = new;
    mprotect(new,sizeof(pwdb), PROT_NONE);
    mprotect(last,sizeof(pwdb), ~PROT_WRITE & 0x7);
    return 0;    
}


/* helper function - parses decrypted pwfile into a pwdb 
 * caller must mlock/scrub/munlock blob memory */
int parse_blob(unsigned char* blob, ptrdiff_t len, pwdb **pwds_out) {
    if (!pwds_out) return -1;
    pwdb *new = (pwdb *)aligned_alloc(PAGE_SIZE, PAGE_SIZE);
    if (!new) return -1;
    blob += crypto_secretbox_ZEROBYTES;
    memcpy(new->site,blob,MAX_SITE_LEN);
    memcpy(new->pwd,blob+MAX_SITE_LEN,MAX_PW_LEN);
    new->changed = 0;
    new->next = *pwds_out;
    *pwds_out = new;            
    mlock(new, PAGE_SIZE);
    mprotect(new,sizeof(pwdb), PROT_NONE);
    return 0;
}

int read_password_entry_file(char *filename, pwdb **pwds_out) {
    if (!filename || !pwds_out || !pwfile_key) return -1;
    int pwfd = open(filename, O_RDONLY);
    if (pwfd < 0) return errno;
    struct stat pwstat;
    if (fstat(pwfd,&pwstat) < 0) {
        close(pwfd);
        return errno;
    }
    unsigned char *encrypted = (unsigned char *)malloc(pwstat.st_size);
    if (!encrypted) { 
        close(pwfd);
        return errno;
    }
    if (read(pwfd,encrypted,pwstat.st_size) != pwstat.st_size) {
        free(encrypted);
        close(pwfd);
        return errno;
    }
    close(pwfd);
    int ptlen = pwstat.st_size - crypto_secretbox_NONCEBYTES;
    int ptpagelen = ((ptlen / PAGE_SIZE) + 1) * PAGE_SIZE;
    unsigned char *plaintext = (unsigned char *)aligned_alloc(PAGE_SIZE,ptpagelen);
    mlock(plaintext,ptpagelen);
    mprotect(pwfile_key,crypto_secretbox_KEYBYTES,PROT_READ);
    unsigned char *ciphertext = encrypted + crypto_secretbox_NONCEBYTES;
    unsigned char *nonce = encrypted;
    if (crypto_secretbox_open(plaintext,ciphertext,ptlen,nonce,pwfile_key) < 0) {
        mprotect(pwfile_key,crypto_secretbox_KEYBYTES, ~PROT_READ & 0x7);
        munlock(plaintext,ptpagelen);
        free(plaintext);
        free(encrypted);
        return DECRYPT_FAIL;
    }

    mprotect(pwfile_key,crypto_secretbox_KEYBYTES, ~PROT_READ & 0x7);
    parse_blob(plaintext,ptlen,pwds_out);
    memset(plaintext,0,ptlen);
    munlock(plaintext,ptpagelen);
    free(plaintext);
    free(encrypted);
    return 0;
}

int read_password_file(pwdb **pwds_out) {
    char pwp[PATH_MAX];
    char pwfn[PATH_MAX];
    unsigned char sitehash[crypto_hash_BYTES] = {0};
    if (get_pw_dir(pwp) < 0) return -1;
    strcat(pwp, "*.bcpw");
    glob_t fl;
    int gr = glob(pwp,0,NULL,&fl);
    if (gr == GLOB_NOMATCH) return 0;
    if (gr != 0) return -2;
    for(int i = 0; i < fl.gl_pathc; i++) {
        if (read_password_entry_file(fl.gl_pathv[i],pwds_out) < 0) goto rpf_err;
        mprotect(*pwds_out,sizeof(pwdb), PROT_READ);
        long slen = strnlen((*pwds_out)->site,MAX_SITE_LEN);
        crypto_hash(sitehash,(*pwds_out)->site,slen);
        get_pw_dir(pwfn);
        // Turn the first 16 bytes of the hash into a hex string
        hexlify_into(pwfn,sitehash,16);
        strcat(pwfn,".bcpw");
        if (strcmp(pwfn,fl.gl_pathv[i]) != 0) goto rpf_err;
        mprotect(*pwds_out, sizeof(pwdb), ~PROT_READ & 0x7);
    }
    globfree(&fl);
    return 0;
rpf_err:
    globfree(&fl);
    return -3;
}

/* helper function: how many entries in a pwdb? */
int pwdb_len(pwdb *pwds) {
    int len = 0;
    pwdb *next;
    while (pwds != NULL) {
        mprotect(pwds, sizeof(pwdb), PROT_READ);
        len++;
        next = pwds -> next;
        mprotect(pwds, sizeof(pwdb), ~PROT_READ & 0x7);
        pwds = next;
    }
    return len;
}

int write_password_entry_file(char *filename, pwdb *pwds) {
    if (!filename || !pwfile_key || !pwds) return -1;
    int blob_len = MAX_PW_LEN + MAX_SITE_LEN + crypto_secretbox_ZEROBYTES;
    int blob_pagelen = ((blob_len / PAGE_SIZE)+1) * PAGE_SIZE;
    unsigned char *pt_blob = aligned_alloc(PAGE_SIZE, blob_pagelen);
    unsigned char *ptbuf;
    mlock(pt_blob,blob_pagelen);
    if (!pt_blob) return -1;
    ptbuf = pt_blob;
    memset(ptbuf,0,crypto_secretbox_ZEROBYTES);
    ptbuf += crypto_secretbox_ZEROBYTES;
    memcpy(ptbuf,pwds->site,MAX_SITE_LEN);
    ptbuf += MAX_SITE_LEN;
    memcpy(ptbuf,pwds->pwd,MAX_PW_LEN);
    mprotect(pwds,sizeof(pwdb),PROT_WRITE);
    pwds->changed = 0;

    /* encrypt the buffer.  Use current time for nonce. */
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    memset(nonce,0,crypto_secretbox_NONCEBYTES);
    time((time_t *)nonce); 
    unsigned char *ciphertext = malloc(blob_len);
    if (!ciphertext) goto clean_ptblob;
    mprotect(pwfile_key,crypto_secretbox_KEYBYTES,PROT_READ);
    crypto_secretbox(ciphertext,pt_blob,blob_len,nonce,pwfile_key);
    mprotect(pwfile_key,crypto_secretbox_KEYBYTES, ~PROT_READ & 0x7);
    /* write the nonce + ciphertext to the file */
    int pwfd = open(filename, O_WRONLY | O_CREAT, 0600);
    if (pwfd < 0) goto clean_ciphertext;
    if (write(pwfd,nonce,crypto_secretbox_NONCEBYTES) < crypto_secretbox_NONCEBYTES) goto clean_pwfile;
    if (write(pwfd,ciphertext,blob_len) < blob_len) goto clean_pwfile;
    close(pwfd);
    free(ciphertext);
    memset(pt_blob,0,blob_len);
    munlock(pt_blob,blob_pagelen);
    free(pt_blob);
    return 0;   

  clean_pwfile:
    close(pwfd);    
  clean_ciphertext:
    free(ciphertext);
  clean_ptblob:  
    memset(pt_blob,0,blob_len);
    munlock(pt_blob,blob_pagelen);
    free(pt_blob);
    return -1;
}

int write_password_file(pwdb *pwds) {
    pwdb *next = pwds;
    char pwfn[PATH_MAX];
    unsigned char sitehash[crypto_hash_BYTES];
    while (pwds != NULL) {
        mprotect(pwds,sizeof(pwdb), PROT_READ);
        if (pwds->changed) {
            long slen = strnlen(pwds->site,MAX_SITE_LEN);
            crypto_hash(sitehash,pwds->site,slen);
            get_pw_dir(pwfn);
            // Turn the first 16 bytes of the hash into a hex string
            hexlify_into(pwfn,sitehash,16);
            strcat(pwfn,".bcpw");
            if(write_password_entry_file(pwfn,pwds) < 0) goto cleanup;              
        }
        next = pwds->next;
        mprotect(pwds,sizeof(pwdb), ~PROT_READ & 0x7);
        pwds = next;
    }
    return 0;

    cleanup:
    mprotect(pwds,sizeof(pwdb), ~PROT_READ & 0x7);
    return -1;
}

void init_db(pwdb **db) {
    *db = aligned_alloc(PAGE_SIZE,PAGE_SIZE);
    memset(*db,0,sizeof(pwdb));
}
