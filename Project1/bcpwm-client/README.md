# bcpwm
This is the (pre-alpha release) client code for BCPWM, the Badly Coded PassWord Manager.  

The bcpwm-cli.c contains the code for a command-line interface (CLI) to BCPWM.  The UX team has not yet completed any standalone GUI or browser plugin implementations.  The CLI and supporting functions can be built using `make all`, and the `install.sh` script will fetch the necessary dependencies, build `bcpwm-cli`, and install it plus a routing rule for the (pre-alpha test) cloud server `bcpwm.badlycoded.net`.

The controller.c module contains the main "control loop" that illustrates how to interact with the main functions provided by the client-side code: it allows setting the master passphrase used to encrypt passwords on disk, listing the sites with passwords currently stored on the client side, retrieving the password for a given site, generating a new password for a given site, manually installing new password policies for a group of sites, initiating the two-step email account registration with the cloud server, and completing the registration given the confirmation code sent via email from the cloud server.

The pwrules.c module contains functions for parsing human-readable JSON files that specify the password policy for a website, and translating them to locally-stored binary ".bcpw" files.  These policies can include:
- a `"chars"` field that specifies all of the valid characters a password can include
- `"min_length"` and `"max_length"` fields that specify the minimum and maximum length of a password
- a `"rules"` field that specifies an ordered list of regular expressions
- a `"min_rules"` field that specifies the minimum number of regular expressions a password must match
- a `"num_rules"` field that specifies how many regular expressions are in the `"rules"` field
The regular expressions allow specifying polices like "at least 1 upper-case character" (`[[:upper:]]`) or "at least one digit" (`\d`) and the min_rules policy allows combination policies like "at least two of:...".
- at least one "site" associated with the policy.  (This allows using the same policy across multiple domains for a company, e.g. `gmail.com` and `google.com`.)
An example generic policy appears in the file "generic.json", and some testing policies are shown in `rtest*.json`.

The pwgen.c module contains functions for generating passwords using a cryptographically strong random number generator and the policy files as described above.  When asked to generate a password for a given site, the module first checks for a local ".bcpw" file corresponding to the site, then checks whether `https://site/bcpwm_rule.json` exists and can be parsed, then checks whether the cloud server has a policy for the site.  If these all fail, it uses a "default" policy.

The pwfile.c module contains functions for manipulating the password database.  It uses mlock and mprotect to limit the exposure of secrets (such as the master encryption key and site passwords) to other processes on the system.  The database itself is encrypted using libsodium's `crypto_secretbox` functionality, which protects both the confidentiality and integrity of its outputs: anyone who does not know the master password cannot read the files or modify them in a way that will not cause decryption to fail.

The pw_dir.c module maintains the directory structure and handles communication with cloud server for synchronization and account registration.

Crypto is provided by the libsodium library.
