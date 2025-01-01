#ifndef CONTROLLER_H
#define CONTROLLER_H
#include "pwfile.h"
int secure_read_password(char *pw_out, int interactive);
int list_passwords(pwdb *pwds, int interactive);
int get_password(pwdb *pwds, char *site, int interactive);
int add_rules_from_file(char *filename, int interactive);
int sync_with_cloud(pwdb *pwds, int interactive);
int register_email(char *email, int interactive);
int confirm_registration(const char *email, char *token, int interactive);
int generate_password(pwdb *pwds, char *site, int interactive);
int interact_loop(pwdb *pwds, int local);
#endif
