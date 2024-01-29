
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/evp.h>

const char *key_range[] = {
    "D76AA478", "E8C7B756", "242070DB", "C1BDCEEE", "F57C0FA", "4787C62A", "A8304613", "FD469501",
    "698098D8", "8B44F7AF", "FFFF5BB1", "895CD7BE", "6B901122", "FD987193", "A679438E", "49B40821",
    "F61E2562", "C040B340", "265E5A51", "E9B6C7AA", "D62F105D", "02441453", "D8A1E681", "E7D3FBC8",
    "21E1CDE6", "C33707D6"
};

void md5_with_key_range(const char *input, const char *key, char outputBuffer[33]) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char digest[MD5_DIGEST_LENGTH];
    unsigned int digest_len;

    mdctx = EVP_MD_CTX_new();
    md = EVP_md5();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, strlen(input));
    EVP_DigestUpdate(mdctx, key, strlen(key));
    EVP_DigestFinal_ex(mdctx, digest, &digest_len);

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        snprintf(&outputBuffer[i * 2], 3, "%02x", (unsigned int)digest[i]);
    }

    outputBuffer[32] = '\0';

    EVP_MD_CTX_free(mdctx);
}

void generate_hash_for_user_input(const char *input, char outputBuffer[33]) {
    md5_with_key_range(input, "", outputBuffer);
}

int main(int argc, char **argv) {
    FILE *dictionary;
    char str[200];
    char hashed_input[33];
    int found = 0;
    int is_hashed;
    char user_input[33];

    if (argc != 2) {
        printf("Usage: %s <user_input>\n", argv[0]);
        return 1;
    }

    printf("Is the dictionary file hashed or plain text? (Enter 1 for hashed, 0 for plain text) : ");
    scanf("%d", &is_hashed);

    if (is_hashed) {
        printf("Enter the hashed MD5 sum: ");
        scanf("%32s", user_input);
    } else {
        generate_hash_for_user_input(argv[1], user_input);
    }

    dictionary = fopen("/home/bhanu/Downloads/password.txt", "r"); //passoword list location (linux filesystem)

    if (dictionary == NULL) {
        perror("Error opening dictionary file");
        return 1;
    }

    while (fgets(str, sizeof(str), dictionary) != NULL) {
        int len_str = strlen(str) - 1;
        if (str[len_str] == '\n') {
            str[len_str] = 0;
        }

        if (is_hashed) {
            // find the position of the first space after the hyphen
            char *hash_start = strchr(str, '-');
            if (hash_start != NULL) {
                hash_start = strchr(hash_start, ' ');
                if (hash_start != NULL) {
                    hash_start++; // move past the space character
                    printf("Comparing:  dictionary='%s', generated='%s'\n", hash_start, user_input);

                    if (strcmp(hash_start, user_input) == 0) {
                        found = 1;
                        printf("Match found! Entry: '%s'\n", str);
                        break;
                    }
                }
            } else {
                printf("Invalid dictionary entry: '%s'\n", str);
            }
        } else {
            for (int i = 0; i < sizeof(key_range) / sizeof(key_range[0]); i++) {
                md5_with_key_range(str, key_range[i], hashed_input);
                printf("Comparing:  dictionary='%s', generated='%s'\n", hashed_input, user_input);

                if (strcmp(hashed_input, user_input) == 0) {
                    found = 1;
                    printf("Match found! Username: '%s', Key: '%s'\n", str, key_range[i]);
                    break;
                }
            }
            if (found) {
                break;
            }
        }
    }

    fclose(dictionary);

    if (!found) {
        printf("No match found.\n");
    }

    return 0;
}
