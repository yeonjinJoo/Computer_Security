import sqlite3, sys, base64

site_arg : str = sys.argv[1]
token_arg : str = sys.argv[2]

print("Writing site rules to rule directory")

# Connect to the database, create the table if doesn't exist
connection = sqlite3.connect('/var/bcpwm/bcpwm.db')
cursor = connection.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS site_reg_table (site Text, token Text, file Text)')

# Read all current users from the database
sql_command = "SELECT site, token, file FROM site_reg_table WHERE site='{}' AND token='{}'"

for (site, token, file) in cursor.execute(sql_command.format(site_arg, token_arg)):
    f = open("/var/bcpwm/rules/" + site + ".bcr", 'wb')
    f.write(base64.b64decode(file))
    f.close()

sql_command = "DELETE from site_reg_table where site='{}' AND token='{}'"
c = cursor.execute(sql_command.format(site_arg, token_arg)).fetchone()

# Write the final table out
connection.commit()
connection.close()

sys.exit(0)
