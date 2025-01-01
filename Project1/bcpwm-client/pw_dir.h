#ifndef PW_DIR_H
#define PW_DIR_H
#include "pwfile.h"

/* help functions to get locations of things */
char *get_cloud_base_url();
int get_bcpwm_dir(char *fn_out);
int get_pw_dir(char *fname_out);
int get_rule_dir(char *fname_out);
void hexlify_into(char *dst, const unsigned char *src, int len);

/* stuff to set up and maintain the application directory */

/* bcpwm_initialize - creates bcpwm_dir, pw_dir and rule_dir 
 * returns 0 on success, negative for errors */
int bcpwm_initialize(void);
/* register_account - calls set_account, contacts cloud server to register email address 
 * master encryption key must be set before calling, since derived cloud key is set up here.
 * returns:
 *  0 on success, 
 * -1 for already registered, 
 * -2 for other errors */
int register_account(char *email);
/* sets local account name, should be called with registered email address */
int set_account(char *email);
const char *get_account();
/* in-app confirmation */
int complete_registration(const char *email, char *token);
/* sync_pwdb - synchronize pwdb to bcpwm cloud
 * calls write_pwdb in pwfile so encryption key must be set
 * uses registered email so set_account must also be called first
 * returns 0 on success, negative for errors */
int sync_pwdb(pwdb *pwds);

#endif