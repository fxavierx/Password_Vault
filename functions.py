import mysql.connector
import hashlib
import random
import string
import sys
from getpass import getpass
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import prettytable
import json
import os
from cryptography.fernet import Fernet


# Function to generate a key (used to encrypt the database credentials) and save it to a file
def generate_db_key():  
    key = Fernet.generate_key()
    with open(".key.key", "wb") as key_file:
        key_file.write(key)


# Function to load the key from the current directory named `.key.key`
def load_db_key():      
    return open(".key.key", "rb").read()


# Function to encrypt the credentials with the Fernet symmetric encryption algorithm
def encrypt_db_credentials(credentials):   
    key = load_db_key()
    f = Fernet(key)
    encrypted_credentials = {}
    for k, v in credentials.items():
        encrypted_credentials[k] = f.encrypt(v.encode()).decode()
    return encrypted_credentials


# Function to decrypt the credentials with the Fernet symmetric encryption algorithm
def decrypt_db_credentials(encrypted_credentials):  
    key = load_db_key()
    f = Fernet(key)
    credentials = {}
    for k, v in encrypted_credentials.items():
        credentials[k] = f.decrypt(v.encode()).decode()
    return credentials


# Function to save the encrypted database credentials to json file
def save_credentials(host, user): 
    # Generate encryption key
    generate_db_key()
    credentials = {"host": host, "user": user}
    encrypted_credentials = encrypt_db_credentials(credentials)
    try:
        with open(".dbconfig.json", "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}
    data.update(encrypted_credentials)
    with open(".dbconfig.json", "w") as f:
        json.dump(data, f)


# Function to connect to the database
def dbconnect():
    while True:
        try:
            # Open the encrypted database credentials file
            with open(".dbconfig.json") as f:
                # Load the JSON data from the file
                encrypted_credentials = json.load(f)
                # Decrypt the database credentials using the decryption function
                credentials = decrypt_db_credentials(encrypted_credentials)
                # Extract the host, user, and password values from the decrypted credentials
                host = credentials["host"]
                user = credentials["user"]
                password = getpass("Enter the database password: ")
        except (FileNotFoundError, KeyError):
            # Prompt user for database login credentials if .dbconfig.json file is not found or credentials are missing
            print("Incorrect or missing database settings. Please provide the following:\n")
            host = input("Database IP address: ")
            user = input("Database username: ")
            password = getpass("Database password: ")
            # Save the entered credentials to file
            save_credentials(host, user)

        try:
            # Attempt to connect to the database using the extracted credentials
            cnx = mysql.connector.connect(
                host=host,
                user=user,
                password=password
            )
            # Return the connection object if the connection is successful
            return host, user, password
        except mysql.connector.Error as err:
            # Print an error message if the connection fails
            clear_screen()
            print("ERROR: {}".format(err))
            # Delete the .dbconfig.json file if the credentials are incorrect
            if os.path.exists(".dbconfig.json"):
                os.remove(".dbconfig.json")
            else:
                print("No credentials file found.")
            # Continue to the next iteration of the loop to try again
            continue
        

# Function to generate the salt
def generateSalt():
    salt = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
    return salt


# Function to configure the database
def config(dbhost, dbuser, dbpassword):
    cnx = mysql.connector.connect(
        host = dbhost,
        user = dbuser,
        password = dbpassword
    )
    # Creates the database
    curs = cnx.cursor()

    # Create vault database and tables
    try:
        curs.execute("CREATE DATABASE vault")
    except Exception as e:
        print("Could not create database.")
        sys.exit(1)
    
    query = "CREATE TABLE vault.master (master_password_hash TEXT NOT NULL, salt TEXT NOT NULL)"
    r = curs.execute(query)

    query = "CREATE TABLE vault.accounts (ID INT AUTO_INCREMENT PRIMARY KEY, website TEXT NOT NULL, url TEXT NOT NULL, email TEXT, username TEXT, password TEXT NOT NULL)"
    r = curs.execute(query)

    # Prompt user to create a master password
    clear_screen()
    print("Welcome to your vault!")
    master_password = ""
    while True:
        master_password = getpass("\nPlease create a master password: ")
        if master_password == getpass("Now enter the master password again: ") and master_password != "":
            break
        clear_screen()
        print("The passwords did not match :(")

    # Hash the master password using sha256 and generate a salt
    master_password_hash = hashlib.sha256(master_password.encode('utf-8')).hexdigest()
    salt = generateSalt()

    # Insert the master password hash and salt into the 'master' table in the database
    query = "INSERT INTO vault.master (master_password_hash, salt) VALUES (%s, %s)"
    val = (master_password_hash, salt)
    curs.execute(query, val)
    cnx.commit()

    # Close the database connection and print a success message
    cnx.close()
    clear_screen()
    print("You have successfully created a master password! :)\n")


# Function to get the master password hash from vault.master
def getMasterPassword(dbhost, dbuser, dbpassword):
    # Connect to database
    cnx = mysql.connector.connect(
        host = dbhost,
        user = dbuser,
        password = dbpassword
    )
    curs = cnx.cursor()

    # Execute query to get master password hash
    query = "SELECT master_password_hash FROM vault.master"
    curs.execute(query)
    master_password_hash = curs.fetchone()

    # Close connection to database and return the master password hash
    cnx.close()
    return master_password_hash[0]


# Function to get the salt from vault.master
def getSalt(dbhost, dbuser, dbpassword):
    # Connect to database
    cnx = mysql.connector.connect(
        host = dbhost,
        user = dbuser,
        password = dbpassword
    )
    curs = cnx.cursor()

    # Query for salt from vault.master table
    query = "SELECT salt FROM vault.master"
    curs.execute(query)

    # Fetch salt value
    salt = curs.fetchone()

    # Close database connection and return salt
    cnx.close()
    return salt[0]


# Function to encrypt the account password
def encryptAccountPassword(password, dbhost, dbuser, dbpassword):
    # Generate an encryption key using the master password hash and salt
    encryption_key = PBKDF2(getMasterPassword(dbhost, dbuser, dbpassword), getSalt(dbhost, dbuser, dbpassword), dkLen=32)
    
    # Set the initialization vector for the encryption algorithm
    iv = b'\x00' * AES.block_size
    
    # Create a new AES encryption object with the encryption key and initialization vector
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv=iv)
    
    # Pad the password to a multiple of the block size
    padded_password = pad(password.encode(), AES.block_size)
    
    # Encrypt the password with AES in CBC mode
    encrypted_password = cipher.encrypt(padded_password)
    
    # Encode the encrypted password in base64 format for storage in the database
    encoded_encrypted_password = base64.b64encode(encrypted_password).decode()
    return encoded_encrypted_password


# Function to decrypt the account password
def decryptAccountPassword(encoded_encrypted_password, dbhost, dbuser, dbpassword):
    # Get the encryption key and initialization vector using the master password and salt
    encryption_key = PBKDF2(getMasterPassword(dbhost, dbuser, dbpassword), getSalt(dbhost, dbuser, dbpassword), dkLen=32)
    iv = b'\x00' * AES.block_size
    
    # Create an AES cipher object in CBC mode with the encryption key and IV
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv=iv)
    
    # Decode the encoded and encrypted password using base64 and decrypt it using the cipher
    encrypted_password = base64.b64decode(encoded_encrypted_password)
    decrypted_password = unpad(cipher.decrypt(encrypted_password), AES.block_size)
    
    # Return the decrypted password as a string
    return decrypted_password.decode()


# Function to clear the screen
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


# Function to display the menu options and handle user input
def menu(dbhost, dbuser, dbpassword):
    options = ['1', '2', '3', '4', '5', '6']

    # Loop until a valid input is given
    while True:
        print("****************  MENU  ****************")
        print("*  1 - Add a new account to the vault  *")
        print("*  2 - Search for an account           *")
        print("*  3 - List all the accounts           *")
        print("*  4 - Generate a strong password      *")
        print("*  5 - Delete an account               *")
        print("*  6 - Exit                            *")
        print("****************************************\n")

        user_input = input('Select an option: ')

        # Check if the user input is a valid option
        if user_input in options:
            break
        
        else:
            # If the input is not valid, display an error message and try again
            clear_screen()
            print("Invalid option. Please try again.\n")

    # Call the corresponding function based on the user input
    if user_input == '1':
        addAccount(dbhost, dbuser, dbpassword)

    elif user_input == '2':
        searchAccount(dbhost, dbuser, dbpassword)

    elif user_input == '3':
        listAllAccounts(dbhost, dbuser, dbpassword)

    elif user_input == '4':
        generatePassword(dbhost, dbuser, dbpassword)

    elif user_input == '5':
        deleteAccount(dbhost, dbuser, dbpassword)

    elif user_input == '6':
        exit()


# Function to add accounts to the database
def addAccount(dbhost, dbuser, dbpassword):
    cnx = mysql.connector.connect(
        host = dbhost,
        user = dbuser,
        password = dbpassword
    )
    # Prompt user for account details
    clear_screen()
    website = input("Enter the website name: ")
    url = input("Enter the website URL: ")
    email = input("Enter the email address: ")
    username = input("Enter the username: ")
    password = getpass("Enter the password: ")

    # Encrypt the account password using the master password and salt
    encrypted_password = encryptAccountPassword(password, dbhost, dbuser, dbpassword)

    # Insert the account details into the 'vault.accounts' table in the database
    curs = cnx.cursor()
    query = "INSERT INTO vault.accounts (website, url, email, username, password) VALUES (%s, %s, %s, %s, %s)"
    val = (website, url, email, username, encrypted_password)
    curs.execute(query, val)
    cnx.commit()

    # Notify user that the account was added successfully
    print("\nAccount added successfully.\n")

    # Ask the user what to do next
    while True:
        print("**********  MENU  **********")
        print("* 1 - Add another account  *")
        print("* 2 - Menu                 *")
        print("* 3 - Quit                 *")
        print("************************ ***\n")

        # Get user input
        choice = input()

        # If the user chooses to go add another account, call the function again
        if choice == '1':
            addAccount(dbhost, dbuser, dbpassword)
            break

        # If the user chooses to go back to the menu, call the menu function and exit the loop.
        if choice == '2':
            clear_screen()
            menu(dbhost, dbuser, dbpassword)
            break

        # If the user chooses to quit the program, exit the program using sys.exit(0)
        elif choice == '3':
            sys.exit(0)

        # If the user enters an invalid choice, display an error message and prompt the user to try again.
        else:
            clear_screen()
            print("Invalid choice. Please try again.")


# Function to search for accounts
def searchAccount(dbhost, dbuser, dbpassword):
    # Prompt user for the search term
    clear_screen()
    search_term = input("Enter search term: ")

    # Check if the search term is empty
    if not search_term:
        # If the search term is empty, call the function to prompt the user again
        searchAccount()

    # Connect to the database)
    cnx = mysql.connector.connect(
        host = dbhost,
        user = dbuser,
        password = dbpassword
    )
    curs = cnx.cursor()

    # Build the SQL query with placeholders for the search term
    query = "SELECT id, website, url, email, username, password FROM vault.accounts WHERE "
    query += "website LIKE %s OR url LIKE %s OR email LIKE %s OR username LIKE %s"
    val = (f'%{search_term}%', f'%{search_term}%', f'%{search_term}%', f'%{search_term}%')

    # Execute the query with the search term placeholders
    curs.execute(query, val)

    # Fetch all the results from the query
    accounts = curs.fetchall()

    # Check if any accounts were found
    if not accounts:
        # If no accounts were found, print a message to the user
        print("\nNo accounts found.")
    else:
        # If accounts were found, create a table to display them
        table = prettytable.PrettyTable()
        table.field_names = ["ID", "Website", "URL", "Email", "Username", "Password"]

        # Loop through the accounts and decrypt the password for display
        for account in accounts:
            encoded_encrypted_password = account[5]
            password = decryptAccountPassword(encoded_encrypted_password, dbhost, dbuser, dbpassword)
            account = list(account)
            account[5] = password
            table.add_row(account)

        # Print the table to the user
        print()
        print(table)

    # Close the database connection
    cnx.close()

    # Ask the user what to do next
    while True:
        print("*************  MENU  *************")
        print("* 1 - Search for another account *")
        print("* 2 - Menu                       *")
        print("* 3 - Quit                       *")
        print("**********************************\n")

        # Get user input
        choice = input()

        # If the user chooses to go search for another account, call the function again
        if choice == '1':
            searchAccount(dbhost, dbuser, dbpassword)
            break

        # If the user chooses to go back to the menu, call the menu function and exit the loop
        if choice == '2':
            clear_screen()
            menu(dbhost, dbuser, dbpassword)
            break

        # If the user chooses to quit the program, exit the program using sys.exit(0)
        elif choice == '3':
            sys.exit(0)

        # If the user enters an invalid choice, display an error message and prompt the user to try again
        else:
            clear_screen()
            print("Invalid choice. Please try again.")


# Function to list all the accounts in the database
def listAllAccounts(dbhost, dbuser, dbpassword):
    clear_screen()
    # Connect to the database
    cnx = mysql.connector.connect(
        host = dbhost,
        user = dbuser,
        password = dbpassword
    )
    curs = cnx.cursor()

    # Execute a SELECT query to retrieve all accounts from the database
    query = "SELECT id, website, url, email, username, password FROM vault.accounts"
    curs.execute(query)

    # Fetch all results and check if there are any accounts in the database
    accounts = curs.fetchall()
    if not accounts:
        print("No accounts found.")
    else:
        # If there are accounts, create a table to display them using PrettyTable
        table = prettytable.PrettyTable()
        table.field_names = ["ID", "Website", "URL", "Email", "Username", "Password"]
        
        # Loop through all accounts and add them to the table
        for account in accounts:
            # Retrieve the encrypted password from the database
            encoded_encrypted_password = account[5]
            # Decrypt the password using the decryptAccountPassword function
            password = decryptAccountPassword(encoded_encrypted_password, dbhost, dbuser, dbpassword)
            # Replace the encrypted password with the decrypted password in the account list
            account = list(account)
            account[5] = password
            table.add_row(account)
        
        # Print the table to the user
        print(table)

    # Close the database connection
    cnx.close()

    # Ask the user what to do next
    while True:
        print("**  MENU  **")
        print("* 1 - Menu *")
        print("* 2 - Quit *")
        print("************\n")

        # Get user input
        choice = input()

        # If the user chooses to go back to the menu, call the menu function and exit the loop
        if choice == '1':
            clear_screen()
            menu(dbhost, dbuser, dbpassword)
            break

        # If the user chooses to quit the program, exit the program using sys.exit(0)
        elif choice == '2':
            sys.exit(0)

        # If the user enters an invalid choice, display an error message and prompt the user to try again
        else:
            clear_screen()
            print("Invalid choice. Please try again.")


# Function to generate a strong password
def generatePassword(dbhost, dbuser, dbpassword):
    # Ask user for the desired length of the password
    clear_screen()
    length = input("Enter the desired length of the password (minimum 8 characters): ")
    # Validate user input to ensure that it is a valid integer and greater than 7
    while not length.isdigit() or int(length) < 8:
        length = input("Invalid input. Enter a valid length for the password (minimum 8 characters): ")
    length = int(length)

    # Ask user if they want to include special characters in the password
    include_special_chars = input("\nDo you want to include special characters? (y/n): ")
    # Validate user input to ensure that it is either 'y' or 'n'
    while include_special_chars.lower() not in ["y", "n"]:
        include_special_chars = input("Invalid input. Do you want to include special characters? (y/n): ")
    include_special_chars = include_special_chars.lower() == "y"

    # Define the set of characters to be used for generating the password
    chars = string.ascii_letters + string.digits
    if include_special_chars:
        chars += string.punctuation

    # Generate the password by selecting random characters from the character set
    password = "".join(random.choice(chars) for _ in range(length))

    # Print the generated password
    clear_screen()
    print(f"Here is your generated password: {password}\n")
    
    # Ask the user what to do next
    while True:
        print("*************  MENU  *************")
        print("* 1 - Generate another password  *")
        print("* 2 - Menu                       *")
        print("* 3 - Quit                       *")
        print("**********************************\n")

        # Get user input
        choice = input()

        # If the user chooses to generate another password, call the function again
        if choice == '1':
            generatePassword(dbhost, dbuser, dbpassword)
            break

        # If the user chooses to go back to the menu, call the menu function and exit the loop
        if choice == '2':
            clear_screen()
            menu(dbhost, dbuser, dbpassword)
            break

        # If the user chooses to quit the program, exit the program using sys.exit(0)
        elif choice == '3':
            sys.exit(0)

        # If the user enters an invalid choice, display an error message and prompt the user to try again
        else:
            clear_screen()
            print("Invalid choice. Please try again.\n")


# Function to delete an account
def deleteAccount(dbhost, dbuser, dbpassword):
    # Connect to database
    cnx = mysql.connector.connect(
        host = dbhost,
        user = dbuser,
        password = dbpassword
    )
    curs = cnx.cursor()

    # Prompt user for account ID
    clear_screen()
    account_id = input("Enter the ID of the account you want to delete: \n")

    # Check if the account exists
    curs.execute("SELECT id FROM vault.accounts WHERE id = %s", (account_id,))
    account = curs.fetchone()

    # If account doesn`t exist, print a message
    if not account:
        print("\nAccount not found.\n")
    else:
        # Delete the account
        curs.execute("DELETE FROM vault.accounts WHERE id = %s", (account_id,))
        cnx.commit()
        print(f"\nAccount with ID {account_id} has been deleted.\n")

    # Close database connection
    cnx.close()

    # Ask the user what to do next
    while True:
        print("***********  MENU  ***********")
        print("* 1 - Delete another account *")
        print("* 2 - Menu                   *")
        print("* 3 - Quit                   *")
        print("******************************\n")

        # Get user input
        choice = input()

        # If the user chooses to delete another account, call the function again
        if choice == '1':
            deleteAccount(dbhost, dbuser, dbpassword)
            break

        # If the user chooses to go back to the menu, call the menu function and exit the loop
        if choice == '2':
            clear_screen()
            menu(dbhost, dbuser, dbpassword)
            break

        # If the user chooses to quit the program, exit the program using sys.exit(0)
        elif choice == '3':
            sys.exit(0)

        # If the user enters an invalid choice, display an error message and prompt the user to try again
        else:
            clear_screen()
            print("Invalid choice. Please try again.")