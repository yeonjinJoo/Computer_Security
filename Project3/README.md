# Project3

## Vulnerability 1 - Unauthenticated Rule Addition : A Gateway for Spoofing attacks
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

![7be4c121-20e8-4a9a-848f-280496b86f95](https://github.com/user-attachments/assets/58e00664-9a72-4683-a9b9-90695d2e1654)


![b81d5d2d-ce9f-415d-bb79-ec352cacc6da](https://github.com/user-attachments/assets/3690af7e-32ba-420c-8fd8-031f293fa549)

**Expected Result**: The system accepts and applies the rule file without requiring authentication, allowing the attacker to define an insecure password generation policy, weakening the site’s overall password security. 


## Vulnerability 2 - Exploiting weak email validation for system tampering 
**Steps to Execute**: 
1. Download the `rtest1.bcr` file and place it in the bcpwm-client directory.
2. In the terminal, send the POST request to the cloud server with normal user address ( not administrative email address ) and rtest1.bcr file ( which has very simple rule )
   ```bash
   curl -v -k --noproxy "*" \
     -X POST "https://bcpwm.badlycoded.net/post-rule/init/csel-xsme-f24-csci4271-23.cselabs.umn.edu/student2" \
     -F "file=@/home/student/bcpwm-client/rtest1.bcr"
   ```
   ![2a8b2a50-fe6c-4ca2-abe1-0c2d7ed3cf41](https://github.com/user-attachments/assets/f7b37614-6fbd-4e9b-96aa-cffec4019879)

   You can see that the request was successfully sent.

4. Log in as student2 and enter the `mail` command to check the mail.
   ```bash
   mail
   ```
   ![725298e1-16d4-4c8d-8452-3f177957fec2](https://github.com/user-attachments/assets/ef5561d4-2279-4148-90fb-31b7a04c3b56)

   Then, you can find that the token value has been correctly received in the mail as follows.

  

4. Return to the original bcpwm-client directory and send a confirm request including the token.
   ```bash
   curl -v -k --noproxy "*" "https://bcpwm.badlycoded.net/post-rule/confirm/csel-xsme-f24-csci4271-23.cselabs.umn.edu/aLsSdYYcYQPo"
   ```
   ![095abd18-4029-4b19-9af5-eddb7264d41d](https://github.com/user-attachments/assets/9eb01470-e6d3-4d69-b47f-e4fba5d6a627)

   It can be observed that the rule upload confirm succeeded even when an email from a normal user, rather than an administrative email address, was used.

5. You can find that the rule is saved in `/var/bcpwm/rules`.
   ![e39e9019-036a-498d-9941-76555057dc7a](https://github.com/user-attachments/assets/e70c7be6-b46c-48c8-b63d-1b80448fa548)



**Expected Result**: The system accepts and applies the rule file without requiring administrative validation, allowing the attacker to upload an insecure password generation policy, weakening the site’s overall password security.

## Vulnerability 3 - Overwriting password and token
**Steps to Execute**: 
1. Use `test' dumb 'kkkk` as user. Thus, hexuser would be 74657374272064756d6220276b6b6b6b.
2. Use "password" as password. Thus, hexpass would be 70617373776f7264.
3. In the terminal, use the /init_client/<string>/<string> API.
   ```bash
   curl -v -k --noproxy "*" \ "https://bcpwm.badlycoded.net/init_client/74657374272064756d6220276b6b6b6b/70617373776f7264" 
   ```
   ![34c0b212-b47c-4b65-aee3-38715e86ddde](https://github.com/user-attachments/assets/ffbe3f10-38b1-4852-a004-0e7807248bb7)
   
   You can see that the request successed.
   
5. Check if the `user`, `password`, and `token` fields in the `user_reg_table` of the database are correctly configured. Navigate to `/var/bcpwm` and enter the command `sqlite3 bcpwm.db`.
6. Search `SELECT * FROM user_reg_table;`.
   
   ![3a2558c0-6725-4fd4-892e-89cdb4597d3f](https://github.com/user-attachments/assets/4790f85a-33e1-4abd-b5ce-500ef3510636)

   As shown below, at the bottom, you can see that `user = test`, `password = dumb`, and `token = kkkk`, confirming that the `password` and `token` values have been overwritten.

**Expected Result**: The system allows unvalidated inputs to be directly injected into the database, enabling attackers to overwrite legitimate user data. This compromises the integrity of stored information and may disrupt normal application functionality.

## Vulnerability 4 - Weak Authentication in Sync Down API can lead to Information Disclosure ( New Vulnerability )
**Steps to Execute**: 
1. Download the file1.txt and file2.txt
2. Navigate to the `/var/bcpwm/tar` directory and save the `file1.txt` and `file2.txt` files in that directory.
3. In that directory, execute the command `sudo tar -cvf test.tar file1.txt file2.txt`. This will create a `test.tar` file.
4. Navigate to the `~/bcpwm-client` directory, and in that directory, execute the command:  
`curl -k --noproxy "*" "https://bcpwm.badlycoded.net/sync_down/test.tar" -o test.tar`
   ![e9f0ea03-ab5d-43bc-926f-0ff221fae5b0](https://github.com/user-attachments/assets/5778ac83-8da0-41e2-af13-e75ec45c56c9)

   As shown in the image above, the `test.tar` file is successfully downloaded without any authentication.
   
   ![7211f731-11c4-434d-bdab-470a3db07b85](https://github.com/user-attachments/assets/138d7db6-0a44-4cbd-99ce-f8f67c93b1e1)

   The `test.tar` file has been successfully saved in the `~/bcpwm-client` directory.

5. To verify that the download was successful, extract the `test.tar` file using the command:  
`tar -xvf test.tar -C ~/bcpwm-client`
   ![50583253-b492-4010-8c97-ad59169b946c](https://github.com/user-attachments/assets/30997909-e7a6-42ed-abff-244f4e8a9d0a)

   As shown in the image, `file1.txt` and `file2.txt` have been successfully extracted and can be seen in the `bcpwm-client` directory.

6. By using the command `cat file1.txt file2.txt`, you can confirm that the files were downloaded successfully.
   
   ![00eb18f9-717f-47e3-a501-474c4e2319a4](https://github.com/user-attachments/assets/4896e222-b2e2-4504-b237-78f0fc832e1e)

**Expected Result**: Anyone, including attackers, who knows the username of a specific user and is aware of the existence of their tar file can download it without restriction. Moreover, these tar files contain sensitive information, such as passwords and password rules. If tar files can be freely downloaded without authentication like this, it creates a significant information disclosure issue.  









