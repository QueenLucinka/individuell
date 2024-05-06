- En individuell inlämningsuppgift för Data och ITsäkerhet. 
Hard kodad, men gör sin magi :)
Hoppas en dag i framtiden ska jag se denna kod och skrata mycket :) Nu iallafall känns det att jag är den bästa hackare i hela världen :)
Real Readme:

This C++ program is designed to enhance password security by performing various operations such as hashing, salting, and password strength validation. It also includes functionalities for storing hashed user data, generating common password hashes, and cracking hashed passwords.
The Password Security Utility is a command-line tool that provides features for:
- Generating secure password hashes using MD5 and SHA256 algorithms.
- Salting user passwords to prevent rainbow table attacks.
- Validating the strength of user passwords.
- Storing hashed user data in files.
- Generating and storing hashes for common passwords.
- Cracking hashed passwords by comparing them with a list of common passwords.
Installation:
Clone the repository:
git clone https://github.com/QueenLucinka/password-security-utility.git
Compile the program:
g++ main.cpp -o password_security_utility -lcrypto
Run the compiled program:
./password_security_utility
Follow the prompts to perform various operations:
Enter an email address and password to store hashed user data.
Choose whether to continue entering user data.
Optionally crack hashed passwords by providing the hash.
