import sqlite3, sys

print("Listing all current user entries:")

# Connect to the database, create the table if doesn't exist
connection = sqlite3.connect('/var/bcpwm/bcpwm.db')
cursor = connection.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS user_pw_table (user Text, password Text)')

# Read all current users from the database
for row in cursor.execute("SELECT user, password FROM user_pw_table ORDER BY user"):
    print("\t{}".format(row))

# Write the final table out
connection.commit()
connection.close()

sys.exit(0)