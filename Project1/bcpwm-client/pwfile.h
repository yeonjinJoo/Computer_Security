#ifndef PWFILE_H
#define PWFILE_H
#define MAX_SITE_LEN 256
#define MAX_PW_LEN 32
#define DECRYPT_FAIL -42

typedef struct pwdlist {
    char site[MAX_SITE_LEN];
    char pwd[MAX_PW_LEN];
    int changed;
    struct pwdlist *next;
} pwdb;

typedef struct slink {
    char site[MAX_SITE_LEN];
    struct slink *next;
} site_list;

int get_upload_password(char *upw);

/* set_encryption_password - set password to be used for encrypting/decrypting 
 * password file.
 * must be called prior to read_password_file/write_password_file
 * will attempt to prevent swapping of key
 * returns 0 for success, <0 on error */
int set_encryption_password(char *epwd);

/* read_password_file - open and read contents of encrypted password file.
 * password file encryption password must already be set.
 * attempts to allocate and prevent swapping of pwdb.
 * returns 0 on success, <0 for errors. */
int read_password_file(pwdb **pwds);

/* write_password_file - write encrypted pwdb to filesystem.
 * password file encryption password must already be set.
 * returns 0 on success, <0 for errors. */
int write_password_file(pwdb *pwds);

/* list_sites - return a list of sites with passwords in pwdb
 * result must be free()d by caller.
 */
site_list* list_sites(pwdb *pwds);

/* get_site_password - find password for a given domain name in pwdb.
 * copies result to pwout.
 * return 0 on success, -1 for not found.
 */
int get_site_password(pwdb *pwds, char *site, char *pw_out);

/* set_site_password - set password for a given domain name in pwdb.
 * if one is already stored, updates the value
 * otherwise a new entry is allocated. returns 0 on success, <0 for errors. */
int set_site_password(pwdb *pwds, char *site, char* pw);

/* Set *db to an empty database */
void init_db(pwdb **db);
#endif
