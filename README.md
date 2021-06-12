# Password Manager
A GUI password manager application to keep your all your passwords safe without transferring them over the internet.

# Features
1. Save your password.
2. Generates strong password.
3. Checks if your password has been pwned.

# Functionality
This application uses API from https://haveibeenpwned.com/ and tells whether your password has ever been hacked but in a more secured way. You don't need to send your password over the internet because someone may hack it in between. This application converts your password into hash code using hash function and sends first five characters of that code to the API and the server returns all hash code password to your system. A for loop then matches your hashed password in the hashed password data you have on your system.

It stores password data locally in json format.
