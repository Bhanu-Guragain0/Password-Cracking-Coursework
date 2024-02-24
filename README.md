
   

# Password Cracking Coursework

## Introduction

This C program is designed to explore password vulnerabilities, emphasizing the importance of strong password practices in cybersecurity. It employs a combination of MD5 hashing and brute force techniques to analyze common password weaknesses.

# System Requirements

- Operating System: Unix/Linux
- Compiler: GCC (GNU Compiler Collection)
- Libraries: OpenSSL (Ensure the development package is installed)

sudo apt-get install libssl-dev

# Usage

To use the program, follow these steps:

# Clone the repository:
   
   git clone https://github.com/Bhanu-Guragain0/Password-Cracking-Coursework.git
   

# Navigate to the cloned directory:
   
   cd Password-Cracking-Coursework
   

# Compile the C program:
   
   gcc myproject.c -o myproject -lssl -lcrypto
   

# Run the program with the following command:
   
   ./myproject /path/to/dictionary/file
   

   Replace `<user_input>` with the input for which you want to find a match.

# Functionality

- The program prompts the user to specify whether the dictionary file is hashed or plaintext.
- If the dictionary file is hashed, the user needs to provide the hashed MD5 sum.
- If the dictionary file is plaintext, the program generates the MD5 hash for the user input and compares it with the entries in the dictionary using a predefined key range for MD5 hashing.
- Once a match is found, the program displays the corresponding entry or username along with the key (if applicable).

# Note

- The dictionary file location is currently hardcoded in the program (`/home/bhanu/Downloads/password.txt`). You may need to modify this path according to your system setup.
- Ensure you have OpenSSL installed on your system to compile the program (`-lcrypto` flag).

# Example

./myproject /path/to/dictionary/file


This command will attempt to find a match for the provided password (`my_password`) in the dictionary file.

## Author

This coursework is authored by Bhanu Guragain.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.Navigate to the cloned directory:
   
   cd Password-Cracking-Coursework
   

3. Compile the C program:
   ```bash
   gcc -o password_cracker password_cracker.c -lcrypto
   ```

4. Run the program with the following command:
   ```bash
   ./password_cracker <user_input>
   ```

   Replace `<user_input>` with the input for which you want to find a match.

### Functionality

- The program prompts the user to specify whether the dictionary file is hashed or plaintext.
- If the dictionary file is hashed, the user needs to provide the hashed MD5 sum.
- If the dictionary file is plaintext, the program generates the MD5 hash for the user input and compares it with the entries in the dictionary using a predefined key range for MD5 hashing.
- Once a match is found, the program displays the corresponding entry or username along with the key (if applicable).

### Note

- The dictionary file location is currently hardcoded in the program (`/home/bhanu/Downloads/password.txt`). You may need to modify this path according to your system setup.
- Ensure you have OpenSSL installed on your system to compile the program (`-lcrypto` flag).

### Example

```bash
./password_cracker my_password
```

This command will attempt to find a match for the provided password (`my_password`) in the dictionary file.

### Author

This coursework is authored by Bhanu Guragain.

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
