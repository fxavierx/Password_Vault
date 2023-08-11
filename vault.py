from functions import *
from getpass import getpass
import time

def main():
    db = dbconnect()
    # Establish cnx based on the returned values from dbconnect()
    cnx = mysql.connector.connect(
        host = db[0],
        user = db[1],
        password = db[2]
    )

    curs = cnx.cursor()
    curs.execute("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = 'vault'")
    result = curs.fetchone()
    
    # If database vault does not exist, run the configuration
    if result is None:
        clear_screen()
        config(db[0], db[1], db[2])
    
    else:
        clear_screen()
        print("Connection successful!\n")
        # Check if master password is correct
        while True:
            entered_password = getpass("Please enter the vault master password: ")
            entered_password_hash = hashlib.sha256(entered_password.encode('utf-8')).hexdigest()
            curs.execute("SELECT * FROM vault.master WHERE master_password_hash = %s", (entered_password_hash,))
            result = curs.fetchone()

            # If master password is incorrect, ask for a new one
            if result is not None:
                time.sleep(1)
                clear_screen()
                print("Logged in successfully! :) \n")
                break
            else:
                time.sleep(1)
                clear_screen()
                print("The password is incorrect.\n")

    # Display the menu
    menu(db[0], db[1], db[2])

  
if __name__ == "__main__":
    clear_screen()
    main()