#ifndef PWRULE_H
#define PWRULE_H
#define MAX_REGEX_RULES 4
#define MAX_RULE_LEN 256
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

struct rule {
    char charset[256];
    char *rex[MAX_REGEX_RULES];
    int min_length;
    int max_length;
    int num_rex;
    int min_rex;
};
int parse_json_file(char *filename);
int get_site_json_file(char *site);
int get_pwr_filename(char *site, char *fn_out);
int parse_pwr_file(char *sitename, struct rule *r_out);
int write_pwr_file(char *sitename, struct rule *r);
int get_cloud_pwr_file(char *sitename);
#endif