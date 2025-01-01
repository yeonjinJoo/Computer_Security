import sqlite3, sys

print("Listing all current site registration entries:")

# Connect to the database, create the table if doesn't exist
connection = sqlite3.connect('/var/bcpwm/bcpwm.db')
cursor = connection.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS site_reg_table (site Text, token Text, file Text)')

# Read all current users from the database
for row in cursor.execute("SELECT site, token, file FROM site_reg_table ORDER BY site"):
    print("\t{}".format(row))

# Write the final table out
connection.commit()
connection.close()

sys.exit(0)