# Project1

## Vulnerability 1 - Elevation of Privilege through Email Input
**Steps to Execute**: 
1. In the terminal, injecting malicious shell commands through the email field `bcpwm-cli -r yeonjin "joo00032@umn.edu; rm -rf /"` (this command is provided in **vulnerability1.txt**).
2. The email input `joo00032@umn.edu; rm -rf /` will be passed to the register_email() function and then to the system() function as part of a shell command. Since the email is not validated, the system will execute the `rm -rf /` command, deleting all files on the system.

**Expected Result**: The system does not validate the email input, allowing the injected command (`rm -rf /`) to be executed. This results in the deletion of critical system files, effectively causing a full system compromise.

## Vulnerability 2 - Tampering through Unauthenticated Rule Addition
**Steps to Execute**: 
1. Download the `vulnerable_rule1.json` and `vulnerable_rule2.json` files and place them in the same directory where you will run the bcpwm-cli commands.
2. Add these rules to the system using the following commands:
   ```bash
   bcpwm-cli -a vulnerable_rule1.json
   bcpwm-cli -a vulnerable_rule2.json
   ```
3. `vulnerable_rule1.json` defines the password rules for *vulnerable.com*, and `vulnerable_rule2.json` defines the password rules for *test.com*. To generate passwords for these sites, use the following commands:
   ```bash
   bcpwm-cli -g [masterpassword] vulnerable.com
   bcpwm-cli -g [masterpassword] test.com
   ```
4. When using `vulnerable_rule1.json`, due to the overly simple rule, the password generated for *vulnerable.com* will always be 'a'. For *test.com*, using the `vulnerable_rule2.json`, a password consisting of 8 characters in the combination of 'a' and 'A' is generated. While this is more complex than the password from *vulnerable_rule1.json*, it still creates a very simple and predictable password.
   
![7be4c121-20e8-4a9a-848f-280496b86f95](https://github.com/user-attachments/assets/9ddb090d-4071-4741-881a-eb5d95558490)

![b81d5d2d-ce9f-415d-bb79-ec352cacc6da](https://github.com/user-attachments/assets/9611d983-1810-4aa7-9ef8-39132b162e2f)


**Expected Result**: The system accepts and applies the rule file without requiring authentication, allowing the attacker to define an insecure password generation policy, weakening the site’s overall password security.


## Vulnerability 3 - Command Injection Leading to System Crash
**Steps to Execute**: 
1. Select the "Generate Password" option by entering: g
2. Input the following command when prompted for a site: test.com; kill -9 -1 #
   ![4fdfa93d-3cfd-48ec-be03-3cddfb8beb9e](https://github.com/user-attachments/assets/85f4d1b5-cc0b-4b0f-b5e4-f34d671eca15)


**Expected Result**
The system will attempt to execute the command and close the connection, resulting in the following message:
![1e5d42a9-93f8-41a3-8453-1ce7882d3dc7](https://github.com/user-attachments/assets/4a402a47-71b6-4453-b860-4fc3ce35269d)


