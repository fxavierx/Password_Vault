# Password-Vault
## 📄 Description:
This is a password vault CLI application developed as the final project for Harvard's CS50 course. The program allows users to securely store and manage their passwords for different accounts. It is written in Python and it stores the accounts information in a MySQL database using encryption to protect sensitive information..

 ## ✨ Features
* Add accounts to the vault
* Search for existing accounts in the vault
* List all accounts in the vault
* Delete accounts from the vault
* Generate strong passwords
  
## 💻 The Code
* The main code (vault.py) is pretty simple and that's because all the functions are stored in functions.py.
* The first function to be called is dbconnect() which establishes the connection with the database. It will first try to load the database IP address and user from the file .dbconfig.jason and if the file does not exist it will ask the user for the information and create the file. Then the user will be asked for the database password, which the user will have to type in every time the code is run for security measures. After establishing the connection, the function will return the values for "host", "user", and "password" which are going to be stored as variables so every function that needs to connect to the database can do so without the user having to type in the information every time. The code then checks if the database "vault" exists and if it doesn't it will call the function config().
* The function config() will create the database "vault" and two tables inside it, one for storing the vault master password and other for storing all the user accounts. Then it will prompt the user to create the master password and store it in it's table after hashing and salting it.
* If the database already exists, the code will prompt the user for the master password and check if it corresponds to the one stored inside the database and if it does it will log the user in and call the function menu().
* The menu() function prompts the user to choose one of the available options (listed in Features) and then calls the corresponding function.
* If the user chooses option 1, the addAcount() function will be called. This function prompts the user for the account information, encrypts the account password using the encryptAccountPassword() function and stores the data inside the "accounts" table in the "vault" database.
* If the user chooses option 2, the searchAccount() function will be called to search inside the "accounts" table for accounts that correspond to the search term and display them inside a table using the PrettyTable() function from the prettytable library.
* If the user chooses option 3, the listAllAccounts() function will be called to print all the stored accounts. The accounts will also be displayed in a pretty table.
* If the user chooses option 4, the generatePassword() function will be called. This function will prompt the user for the desired password length (minimum 8 characters) and also if special characters are desired or not. The strong password will be generated and printed to te user.
* If the user chooses option 5, the deleteAccount() function will be called to delete an existing account based on it's ID number.
* If the user chooses option 6 the application will exit.

## 🚀 Installation

* Clone the GitHub repository
```
git clone git@github.com:fxavierx/Password-Vault.git
```
* Install the requirements
```
pip3 install -r requirements.txt
```
## ☕️ Usage
* Start the MySQL service
```
mysql.server start
```
>You might need to create a user for your MySQL database if you don't have one already.
* Run the code
```
python3 vault.py
```
* Enter the database information
>If you are accessing it localy, type "localhost" in the IP address field.
* Create a master password for your vault
* Choose from the menu options
