import sqlite3, sys

# Path to the server's SQL database
DB_PATH : str = "/var/bcpwm/bcpwm.db"

if len(sys.argv) < 5:
    print("Not enough arguments (use empty strings for unneeded values)")
    sys.exit(-1)

mode_arg : str = sys.argv[1] # Type of query to make
user_arg : str = sys.argv[2] # User/site to add/delete/modify
password_arg : str = sys.argv[3] # Relevant password (if needed)
token_arg : str = sys.argv[4] # Relevant token (if needed)
file_arg : str = sys.argv[5] # Relevant file (if needed)

# Legal options for the mode argument
CHECK_USER : str = "--check-user" # check if user exists
CHECK_PASS : str = "--check-pass" # check if user password is correct
CHECK_TOKEN : str = "--check-token" # check if registration token is correct
CHECK_SITE_TOKEN : str = "--check-site-token" # check if site registration token is correct
CREATE_REG : str = "--create-reg" # create a new registration entry
CREATE_SITE_REG : str = "--create-site-reg" # create a new site registration entry
CREATE_USER : str = "--create-user" # create a new user
DELETE_REG : str = "--delete-reg" # delete a user's registration entries
DELETE_SITE_REG : str = "--delete-site-reg" # delete an existing site registration
DELETE_USER : str = "--delete-user" # delete an existing user
VALID_MODES = [CHECK_USER, CHECK_PASS, CHECK_TOKEN, CHECK_SITE_TOKEN,
             CREATE_REG, CREATE_SITE_REG, CREATE_USER,
             DELETE_REG, DELETE_SITE_REG, DELETE_USER]

# Argument should be of the form e.g. `-du` for delete user or `-cu` for check user
if mode_arg not in VALID_MODES:
    print("Invalid mode for registration database SQL call")
    sys.exit(-2)

# Open bcpwm database
connection = sqlite3.connect(DB_PATH)
cursor = connection.cursor()
# check that tables all exist, otherwise create them
cursor.execute('CREATE TABLE IF NOT EXISTS user_reg_table (user Text, password Text, token Text)')
cursor.execute('CREATE TABLE IF NOT EXISTS site_reg_table (site Text, token Text, file Text)')
cursor.execute('CREATE TABLE IF NOT EXISTS user_pw_table (user Text, password Text)')

if mode_arg == CHECK_USER:
    sql_command = "SELECT count(*) from user_pw_table where user='{}'"
    c = cursor.execute(sql_command.format(user_arg)).fetchone()
    connection.commit()
    connection.close()
    if c[0] == 0: sys.exit(0) # user doesn't exist
    else: sys.exit(-1) # user already exists
elif mode_arg == CHECK_PASS:
    sql_command = "SELECT count(*) from user_pw_table where user='{}' and password='{}'"
    c = cursor.execute(sql_command.format(user_arg, password_arg)).fetchone()
    connection.commit()
    connection.close()
    if c[0] == 0: sys.exit(-1) # user+pwd not in the database
    else: sys.exit(0) # user+pwd exist and match
elif mode_arg == CHECK_TOKEN:
    sql_command = "SELECT count(*) from user_reg_table where user='{}' AND password='{}' AND token='{}'"
    c = cursor.execute(sql_command.format(user_arg, password_arg, token_arg)).fetchone()
    connection.commit()
    connection.close()
    if c[0] == 0: sys.exit(-1) # user+token don't exist already
    else: sys.exit(0) # token exists and matches
elif mode_arg == CREATE_REG:
    sql_command = "INSERT INTO user_reg_table (user, password, token) VALUES ('{}', '{}', '{}')"
    cursor.execute(sql_command.format(user_arg, password_arg, token_arg))
    connection.commit()
    connection.close()
    sys.exit(0)
elif mode_arg == CREATE_SITE_REG:
    sql_command = "INSERT INTO site_reg_table (site, token, file) VALUES ('{}', '{}', '{}')"
    cursor.execute(sql_command.format(user_arg, token_arg, file_arg)) # TODO: file
    connection.commit()
    connection.close()
    sys.exit(0)
elif mode_arg == CREATE_USER:
    sql_command = "INSERT INTO user_pw_table (user, password) VALUES ('{}', '{}')"
    cursor.execute(sql_command.format(user_arg, password_arg))
    connection.commit()
    connection.close()
    sys.exit(0)
elif mode_arg == DELETE_REG:
    sql_command = "DELETE from user_reg_table where user='{}'"
    c = cursor.execute(sql_command.format(user_arg)).fetchone()
    connection.commit()
    connection.close()
    sys.exit(0)
elif mode_arg == DELETE_SITE_REG:
    sql_command = "DELETE from site_reg_table where site='{}'"
    c = cursor.execute(sql_command.format(user_arg)).fetchone()
    connection.commit()
    connection.close()
    sys.exit(0)
elif mode_arg == DELETE_USER:
    sql_command = "DELETE from user_reg_table where user='{}'"
    c = cursor.execute(sql_command.format(user_arg)).fetchone()
    connection.commit()
    connection.close()
    sys.exit(0)

sys.exit(0)