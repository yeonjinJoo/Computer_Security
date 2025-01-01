#ifndef PWGEN_H
#define PWGEN_H
/* seed/re-seed the RNG : seed_rand MUST be called before gen_password*/
void seed_rand(void);
void reseed_rand(void);

/* generate a password for site site, store in pwd_out. 
 * Assumes:
 * rand_seed already called
 * pwd_out points to a MAX_PWD_LEN buffer
 * returns < 0 on error, 0 on success.
 */
 int gen_password(char *site, char *pw_out);
 #endif
