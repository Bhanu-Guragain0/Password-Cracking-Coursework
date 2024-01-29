# Password-Cracking-Coursework in c

## Introduction

This C program is designed to explore password vulnerabilities, emphasizing the importance of strong password practices in cybersecurity. It employs a combination of MD5 hashing and brute force techniques to analyze common password weaknesses.

## System Requirements

- Operating System: Unix/Linux
- Compiler: GCC (GNU Compiler Collection)
- Libraries: OpenSSL (Ensure the development package is installed)

sudo apt-get install libssl-dev


## Compilation

Compile the code using the following command:


gcc myproject.c -o myproject -lssl -lcrypto


## Usage

Run the compiled program with the path to the dictionary file as a command-line argument. Optionally, specify whether the dictionary file contains hashed or plaintext entries.

./myproject /path/to/dictionary/file

### User Interaction

1. When prompted, enter '1' for hashed entries or '0' for plaintext entries.
2. If hashed, enter the hashed MD5 sum.

### Example

./myproject /home/user/passwords.txt

Is the dictionary file hashed or plain text? (Enter 1 for hashed, 0 for plain text): 1
Enter the hashed MD5 sum: abcdef123456...


## Output

The program compares the provided hash with entries in the dictionary file, indicating if a match is found.

## Recommendation and Future Enhancement

Recommendation

Consider incorporating a graphical user interface (GUI) for broader accessibility.

Future Enhancement

Explore advanced hashing algorithms (e.g., AES, SHA) and additional attack methods. Extend support for various file types and incorporate functions for website security testing.

## Ethical Use

Please use this program responsibly and for educational purposes only. Unauthorized or malicious use is strictly prohibited.
