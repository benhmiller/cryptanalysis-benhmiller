////////////////////////////////////////////////////////////////////////////////
//
//  File           : cs642-cryptanalysis-impl.c
//  Description    : This is the development program for the cs642 first project
//  that
//                   performs cryptanalysis on ciphertext of different ciphers.
//                   See associated documentation for more information.
//
//   Author        : Benjamin Miller
//   Last Modified : 02 / 28 / 2024
//

// Include Files
#include <compsci642_log.h>
#include <string.h>
#include <stdlib.h>

// Project Include Files
#include "cs642-cryptanalysis-support.h"


//
// Functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642StudentInit
// Description  : This is a function that is called before any cryptanalysis
//                occurs. Use it if you need to initialize some datastructures
//                you may be reusing across ciphers.
//
// Inputs       : void
// Outputs      : 0 if successful, -1 if failure

int cs642StudentInit(void) {
  /*// Plaintext
    char *plaintext = malloc(27); // Allocating memory for 26 characters + null terminator
    strcpy(plaintext, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    int plen = strlen(plaintext);
    printf("Plaintext: %s\n", plaintext);

    // Key
    char *key = malloc(2); // Allocating memory for 1 character + null terminator
    char *key2 = malloc(2); // Allocating memory for 1 character + null terminator
    strcpy(key, "1");
    strcpy(key2, "2");
    int keyLen = strlen(key);
    int keyLen2 = strlen(key2);
    printf("Key: %s\n", key);
    printf("Key2: %s\n", key2);

    // Ciphertext
    char *ciphertext = malloc(plen + 1); // Allocating memory for plen characters + null terminator
    memset(ciphertext, 0x00, plen + 1);
    cs642Encrypt(CIPHER_ROTX, key, keyLen, plaintext, plen, ciphertext, plen);
    printf("Ciphertext: %s\n", ciphertext);

    // Ciphertext 2
    char *ciphertext2 = malloc(plen + 1); // Allocating memory for plen characters + null terminator
    memset(ciphertext2, 0x00, plen + 1);
    cs642Encrypt(CIPHER_ROTX, key2, keyLen2, plaintext, plen, ciphertext2, plen);
    printf("Ciphertext: %s\n", ciphertext2);

    // Check decryption
    printf("Plaintext: %s\n", plaintext);
    cs642Decrypt(CIPHER_ROTX, key, keyLen, plaintext, plen, ciphertext, plen);
    printf("Decrypted back: %s\n", plaintext);

    // Free dynamically allocated memory
    free(plaintext);
    free(key);
    free(ciphertext);
*/
    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642PerformROTXCryptanalysis
// Description  : This is the function to cryptanalyze the ROT X cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                plen - the length of the plaintext
//                key - the place to put the key in
// Outputs      : 0 if successful, -1 if failure

int cs642PerformROTXCryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, uint8_t *key) {

  // Local Variable
  char **plaintext_possibilities = (char **)malloc(26 * sizeof(char *)); 
  if (plaintext_possibilities == NULL) {
    perror("Memory allocation failed");
    exit(EXIT_FAILURE);
  }

  // Calculate All Possible Shifts of the Ciphertext
  for(int k = 0; k < 26; k++) {
    plaintext_possibilities[k] = (char *)malloc(clen + 1);
    if (plaintext_possibilities[k] == NULL) {
      perror("Memory allocation failed");
      exit(EXIT_FAILURE);
    }

    // Shift each character in ciphertext by current key value (exclude spaces)
    for(int i = 0; i < clen; i++) {
      if(ciphertext[i] != 32) { // Exclude Spaces in Shift
        plaintext_possibilities[k][i] = (ciphertext[i] - 'A' - k + 26) % 26 + 'A';
      }
      else { // Preserve Spaces in Plaintext
        plaintext_possibilities[k][i] = ' ';
      }
    }
    plaintext_possibilities[k][clen] = '\0'; // Null Terminate Translation
  }

  // Locate Valid Plaintext From Possibilities
  for (int i = 0; i < 26; i++) {
    // Identify if translation contains two most frequent words ("ALICE" and "THE")
    char* result_the = strstr(plaintext_possibilities[i], " THE ");
    char* result_alice = strstr(plaintext_possibilities[i], " ALICE ");
    if(result_the != NULL && result_alice != NULL) {
      strcpy(plaintext, plaintext_possibilities[i]);
      *key = i;
      break;
    }
  }
  printf("Key: %d\n", *key);

  // Free Allocated Memory
  for (int i = 0; i < 26; i++) {
    free(plaintext_possibilities[i]);
  }
  free(plaintext_possibilities);

  // Return successfully
  return (0);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642PerformVIGECryptanalysis
// Description  : This is the function to cryptanalyze the Vigenere cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                plen - the length of the plaintext
//                key - the place to put the key in
// Outputs      : 0 if successful, -1 if failure

int cs642PerformVIGECryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, char *key) {

  // ADD CODE HERE
  /*
  int most_frequent_idx = -1;
  int greatest_frequency = -1;
  for(int i = 0; i < cs642GetDictSize(); i++) {
    if(strcmp(cs642GetWordfromDict(i).word, "THE") == 0) {
      printf("Word: %s\n", cs642GetWordfromDict(i).word);
      printf("Frequency: %d\n", cs642GetWordfromDict(i).count);
      printf("\n");
    }
    if(cs642GetWordfromDict(i).count > greatest_frequency) {
      printf("Word: %s\n", cs642GetWordfromDict(i).word);
      printf("Frequency: %d\n", cs642GetWordfromDict(i).count);
      most_frequent_idx = i;
      greatest_frequency = cs642GetWordfromDict(i).count;
    }
  }
  
  printf("Word: %s\n", cs642GetWordfromDict(most_frequent_idx).word);
  printf("Frequency: %d\n", cs642GetWordfromDict(most_frequent_idx).count);
  // Print and Free Each Translation
  for (int i = 0; i < 26; i++) {
    printf("Key %d: %s\n", i + 1, plaintext_possibilities[i]);
    free(plaintext_possibilities[i]);
  }
  */
  // Return successfully
  return (0);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642PerformSUBSCryptanalysis
// Description  : This is the function to cryptanalyze the substitution cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                plen - the length of the plaintext
//                key - the place to put the key in
// Outputs      : 0 if successful, -1 if failure

int cs642PerformSUBSCryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, char *key) {

  // ADD CODE HERE

  // Return successfully
  return (0);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642StudentCleanUp
// Description  : This is a clean up function called at the end of the
//                cryptanalysis of the different ciphers. Use it if you need to
//                release memory you allocated in cs642StudentInit() for
//                instance.
//
// Inputs       : void
// Outputs      : 0 if successful, -1 if failure

int cs642StudentCleanUp(void) {

  // ADD CODE HERE IF NEEDED

  // Return successfully
  return (0);
}