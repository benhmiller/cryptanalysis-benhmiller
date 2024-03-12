////////////////////////////////////////////////////////////////////////////////
//
//  File           : cs642-cryptanalysis-impl.c
//  Description    : This is the development program for the cs642 first project
//  that
//                   performs cryptanalysis on ciphertext of different ciphers.
//                   See associated documentation for more information.
//
//   Author        : Benjamin Miller
//   Last Modified : 03 / 11 / 2024
//

// Include Files
#include <compsci642_log.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <ctype.h>

// Project Include Files
#include "cs642-cryptanalysis-support.h"

// Declare Global Variables (for letter frequency)
#define ALPHABET_SIZE 26

// Declare the array as a global variable
double letter_frequencies[ALPHABET_SIZE] = {0};

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
  int dictSize = cs642GetDictSize();

  // Read words from the dictionary and update counts
  int total_word_count = 0;
  for (int i = 0; i < dictSize; i++) {
    DictWord wordInfo = cs642GetWordfromDict(i); // Obtain individual word
    char *word = wordInfo.word;
    int count = wordInfo.count;

    for (int j = 0; word[j] != '\0'; j++) { // Traverse characters of current word
      char ch = word[j];
      if (isalpha(ch)) {
        ch = toupper(ch); // Convert to uppercase
        letter_frequencies[ch - 'A'] += count; // Increment by number of occurrences of letter / # words (i.e. 1 * count of word = count)
        total_word_count += count;
      }
      //letter_frequencies[word[j] - 'A'] += count; // Increment by number of occurrences of letter / word (i.e. 1 * count of word = count)
      //total_word_count += count;
    }
  }

  // Convert Counts to Frequencies
  for (int i = 0; i < ALPHABET_SIZE; i++) {
    letter_frequencies[i] = letter_frequencies[i] / (double)total_word_count;
  }
  
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
// Function to perform Kasiski examination and return the probable key length

double calculateChiSquared(double observed[], double expected[]) {
    double chiSquared = 0.0;
    for (int i = 0; i < 26; i++) {
        chiSquared += ((observed[i] - expected[i]) * (observed[i] - expected[i])) / expected[i];
    }
    return chiSquared;
}

int findBestKey(double observed[], double expected[]) {
    int bestKey = 0;
    double minChiSquared = 1000000000;

    for (int key = 0; key < 26; key++) {
        // Shift observed frequencies by key (equivalent to a group-wise ROT-KEY cipher shift)
        double shifted_observed[26];
        for (int i = 0; i < 26; i++) {
          shifted_observed[i] = observed[(i + key + 26) % 26];
        }

        // Calculate the Chi-Squared statistic for the current key
        double chiSquared = calculateChiSquared(shifted_observed, expected);

        // Update the best key if the current shift is better
        if (chiSquared < minChiSquared) {
            minChiSquared = chiSquared;
            bestKey = key;
        }
    }
    return bestKey;
}

int cs642PerformVIGECryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, char *key) {
  // Iterate through all possible key lengths
  for(int possible_key = 6; possible_key <= 11; possible_key++) {
    char group_keys[possible_key + 1]; // Each idx corresponds to best cipher group key (complete array = key candidate)

    // Form cipher groups by assigning each char index in cipher text to a group number (1 - key length)
    char** cipher_groups = (char**)malloc(sizeof(char*) * possible_key); // Array of all ciphertext groups
    if (cipher_groups == NULL) {
      fprintf(stderr, "Memory allocation failed\n");
      return 1; // Return an error code
    }

    // Allocate memory for each cipher group
    for (int i = 0; i < possible_key; i++) {
      cipher_groups[i] = (char*)malloc(sizeof(char) * (clen / possible_key) + 1);
      if (cipher_groups[i] == NULL) {
        fprintf(stderr, "Memory allocation for group %d failed\n", i);
        for (int j = 0; j < i; j++) {
          free(cipher_groups[j]);
        }
        free(cipher_groups);
        return 1;
      }
    }

    // Form groups from the ciphertext
    for (int i = 0; i < clen; i++) {
      int group_index = i % possible_key; // Calculate group index of ith letter
      cipher_groups[group_index][i / possible_key] = ciphertext[i]; // Add ith letter to position i / key_length in group
    }

    // Null-terminate each group (allows groups to be viewed as strings)
    for (int group_index = 0; group_index < possible_key; group_index++) {
      cipher_groups[group_index][clen / possible_key] = '\0';
    }

    // Calculate Letter Frequencies in Each Group and Determine Most Likely Key for Each Group
    for (int group_index = 0; group_index < possible_key; group_index++) {
      // Count Letter Occurrences in Each Group
      double observed_letter_frequencies[26] = {0};
      int total_group_chars = 0;
      for(int i = 0; cipher_groups[group_index][i] != '\0'; i++) {
        if (isalpha(cipher_groups[group_index][i])) {
          char temp = toupper(cipher_groups[group_index][i]); // Convert to uppercase
          observed_letter_frequencies[temp - 'A']++; // Count letter occurrence
          total_group_chars++; // Increment total number of characters
        }
      }

      // Convert Counts to Frequencies
      for(int i = 0; i < 26; i++) {
        observed_letter_frequencies[i] = observed_letter_frequencies[i] / (double)total_group_chars;
      }

      // Determine Best Key for Current Group
      group_keys[group_index] = findBestKey(observed_letter_frequencies, letter_frequencies);
    }
    
    // Store Current Group Key in Key Variable (for potential break and return)
    for (int i = 0; i < possible_key; i++) {
      key[i] = group_keys[i] + 'A';
    }

    // Decrypt Ciphertext with Key Candidate
    cs642Decrypt(CIPHER_VIGE, key, possible_key, plaintext, plen, ciphertext, clen);

    // Identify if decryption contains two most frequent words ("ALICE" and "THE")
    char* result_the = strstr(plaintext, " THE ");
    char* result_alice = strstr(plaintext, " ALICE ");
    if(result_the != NULL && result_alice != NULL) { // Free Allocated Data and Break Loop (Key + Plaintext Found)
      for (int i = 0; i < possible_key; i++) {
        free(cipher_groups[i]);
      }
      free(cipher_groups);
      break;
    }
    else { // Free Allocated Data and Continue w/ Next Key Length
      for (int i = 0; i < possible_key; i++) {
        free(cipher_groups[i]);
      }
      free(cipher_groups);
    }
  }

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