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
#include <float.h>
#include <time.h>

// Project Include Files
#include "cs642-cryptanalysis-support.h"

// Declare Global Variables
#define ALPHABET_SIZE 26
#define MAX_ATTEMPTS 750
#define MAX_FAILED_KEYS 200
#define MIN_TRIGRAM_FREQUENCY 0.005

// Struct to represent a trigram and its frequency
struct TrigramFrequency {
    char trigram[4];  // Assuming trigrams are represented as three characters plus null terminator
    double frequency;
};

// Struct to represent a bigram and its frequency
struct BigramFrequency {
    char bigram[3];  // Assuming bigrams are represented as two characters plus null terminator
    double frequency;
};

// Struct to represent a letter and its frequency
struct LetterFrequency {
    char letter;
    double frequency;
};

// Global Variables for Storing Letter, Bigram, and Trigram Frequency
struct LetterFrequency letter_frequencies_struct[ALPHABET_SIZE] = {0};
double letter_frequencies[ALPHABET_SIZE] = {0};
double bigram_frequencies[ALPHABET_SIZE][ALPHABET_SIZE] = {0};
double trigram_frequencies[ALPHABET_SIZE][ALPHABET_SIZE][ALPHABET_SIZE] = {0};

struct BigramFrequency bigramArray[ALPHABET_SIZE * ALPHABET_SIZE];
struct TrigramFrequency trigramArray[ALPHABET_SIZE * ALPHABET_SIZE * ALPHABET_SIZE];


// Functions

// Function to compare two letter frequencies for sorting
int compareLetterFrequencies(const void *a, const void *b) {
  const struct LetterFrequency *letterA = (const struct LetterFrequency *)a;
  const struct LetterFrequency *letterB = (const struct LetterFrequency *)b;

  // Compare frequencies in descending order
  if (letterB->frequency > letterA->frequency) {
    return 1;
  } else if (letterB->frequency < letterA->frequency) {
    return -1;
  } else {
    return 0;
  }
}

// Function to compare two bigram frequencies for sorting
int compareBigramFrequencies(const void *a, const void *b) {
  const struct BigramFrequency *bigramA = (const struct BigramFrequency *)a;
  const struct BigramFrequency *bigramB = (const struct BigramFrequency *)b;

  // Compare frequencies in descending order
  if (bigramB->frequency > bigramA->frequency) {
    return 1;
  } else if (bigramB->frequency < bigramA->frequency) {
    return -1;
  } else {
    return 0;
  }
}

// Function to compare two trigram frequencies for sorting
int compareTrigramFrequencies(const void *a, const void *b) {
    const struct TrigramFrequency *trigramA = (const struct TrigramFrequency *)a;
    const struct TrigramFrequency *trigramB = (const struct TrigramFrequency *)b;

    // Compare frequencies in descending order
    if (trigramB->frequency > trigramA->frequency) {
        return 1;
    } else if (trigramB->frequency < trigramA->frequency) {
        return -1;
    } else {
        return 0;
    }
}

// Returns number of words from dictionary found in plaintext
int getNumberWordsFromDict(char *plaintext) {
  int num_words_from_dict = 0;
  for(int i = 0; i < cs642GetDictSize(); i++) {
    if(strstr(plaintext, cs642GetWordfromDict(i).word) != NULL) {
      //printf("%s\n", cs642GetWordfromDict(i).word);
      num_words_from_dict++;
    }
  }
  //printf("WORDS FROM DICT: %d\n", num_words_from_dict);
  //printf("PERCENT WORDS FROM DICT: %f\n", num_words_from_dict / (double)cs642GetDictSize());
  //return num_words_from_dict / (double)cs642GetDictSize();
  return num_words_from_dict;
}

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

  // Initialize Letters in Letter Frequency Array
  for(int i = 0; i < ALPHABET_SIZE; i++) {
    letter_frequencies_struct[i].letter = i + 'A';
  }

  // Read words from the dictionary and update counts
  int total_word_count = 0;
  for (int i = 0; i < dictSize; i++) {
    /*** COUNT LETTERS ***/
    DictWord wordInfo = cs642GetWordfromDict(i); // Obtain individual word
    char *word = wordInfo.word;
    int count = wordInfo.count;

    for (int j = 0; word[j] != '\0'; j++) { // Traverse characters of current word
      char ch = word[j];
      if (isalpha(ch)) {
        ch = toupper(ch); // Convert to uppercase
        letter_frequencies_struct[ch - 'A'].frequency += count; // Increment by number of occurrences of letter / # words (i.e. 1 * count of word = count)
        letter_frequencies[ch - 'A'] += count;
        total_word_count += count;
      }
    }
  }

  // Convert Counts to Frequencies
  for (int i = 0; i < ALPHABET_SIZE; i++) {
    letter_frequencies_struct[i].frequency = letter_frequencies_struct[i].frequency / (double)total_word_count;
    letter_frequencies[i] = letter_frequencies[i] / (double)total_word_count;
  }

  /*** COUNT BIGRAMS ***/
  int totalBigrams = 0;
  for (int i = 0; i < dictSize; i++) {
    DictWord wordInfo = cs642GetWordfromDict(i); // Obtain individual word
    char *word = wordInfo.word;
    int count = wordInfo.count;

    for(int i = 0; word[i] != '\0' && word[i + 1] != '\0'; i++) {
      if (isalpha(word[i]) && isalpha(word[i + 1])) {
        char first = toupper(word[i]);
        char second = toupper(word[i + 1]);
        bigram_frequencies[first - 'A'][second - 'A'] += count;
        totalBigrams++;
      }
    }
  }

  // Convert counts to frequencies
  for(int i = 0; i < ALPHABET_SIZE; i++) {
    for (int j = 0; j < ALPHABET_SIZE; j++) {
      bigram_frequencies[i][j] /= totalBigrams;
    }
  }
  // Sort Bigrams into Array by Descending Frequency
  int index = 0;
  for (int i = 0; i < ALPHABET_SIZE; i++) {
    for (int j = 0; j < ALPHABET_SIZE; j++) {
      // Create a bigram string (2 characters plus null terminator)
      char bigram[3] = {i + 'A', j + 'A', '\0'};
              
      // Populate the struct
      strcpy(bigramArray[index].bigram, bigram);
      bigramArray[index].frequency = bigram_frequencies[i][j];

      // Move to the next index
      index++;
    }
  }
  qsort(bigramArray, ALPHABET_SIZE * ALPHABET_SIZE, sizeof(struct BigramFrequency), compareBigramFrequencies);

  // Print the sorted bigram frequencies
  //for (int i = 0; i < ALPHABET_SIZE * ALPHABET_SIZE; i++) {
  //    printf("Bigram: %s; Frequency: %f\n", bigramArray[i].bigram, bigramArray[i].frequency);
  //}

  /*** COUNT TRIGRAMS ***/
  // Count Trigrams in Dictionary
  int totalTrigrams = 0;
  for (int i = 0; i < dictSize; i++) {
    DictWord wordInfo = cs642GetWordfromDict(i); // Obtain individual word
    char *word = wordInfo.word;
    int count = wordInfo.count;

    for(int i = 0; word[i] != '\0' && word[i + 1] != '\0' && word[i + 2] != '\0'; i++) {
      if (isalpha(word[i]) && isalpha(word[i + 1]) && isalpha(word[i + 2])) {
        char first = toupper(word[i]);
        char second = toupper(word[i + 1]);
        char third = toupper(word[i + 2]);
        trigram_frequencies[first - 'A'][second - 'A'][third - 'A'] += count;
        totalTrigrams++;
      }
    }
  }

  // Convert counts to frequencies
  for(int i = 0; i < ALPHABET_SIZE; i++) {
    for (int j = 0; j < ALPHABET_SIZE; j++) {
      for (int k = 0; k < ALPHABET_SIZE; k++) {
        trigram_frequencies[i][j][k] /= totalTrigrams;
      }
    }
  }

  // Sort Trigrams into Array by Descending Frequency
  index = 0;
  for (int i = 0; i < ALPHABET_SIZE; i++) {
    for (int j = 0; j < ALPHABET_SIZE; j++) {
      for (int k = 0; k < ALPHABET_SIZE; k++) {
        // Create a trigram string (3 characters plus null terminator)
        char trigram[4] = {i + 'A', j + 'A', k + 'A', '\0'};
              
        // Populate the struct
        strcpy(trigramArray[index].trigram, trigram);
        trigramArray[index].frequency = trigram_frequencies[i][j][k];

        // Move to the next index
        index++;
      }
    }
  }
  // Sort the trigram array
  qsort(trigramArray, ALPHABET_SIZE * ALPHABET_SIZE * ALPHABET_SIZE, sizeof(struct TrigramFrequency), compareTrigramFrequencies);

  // Print the sorted trigram frequencies
  //for (int i = 0; i < ALPHABET_SIZE * ALPHABET_SIZE * ALPHABET_SIZE; i++) {
  //  printf("Trigram: %s; Frequency: %f\n", trigramArray[i].trigram, trigramArray[i].frequency);
  //}
  
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
    /*char* result_the = strstr(plaintext_possibilities[i], " THE ");
    char* result_alice = strstr(plaintext_possibilities[i], " ALICE ");
    if(result_the != NULL && result_alice != NULL) {
      strcpy(plaintext, plaintext_possibilities[i]);
      *key = i;
      break;
    }*/
    if(getNumberWordsFromDict(plaintext_possibilities[i]) > 400) { // Checks if at least
      strcpy(plaintext, plaintext_possibilities[i]);
      *key = i;
      break;
    }
  }
  //cs642Decrypt(CIPHER_ROTX, key, ALPHABET_SIZE, plaintext, plen, ciphertext, clen);
  //printf("CIPHER WORDS: %d\n", getNumberWordsFromDict(plaintext));

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

double calculateChiSquared(double observed[], double expected[]) {
    double chiSquared = 0.0;
    for (int i = 0; i < 26; i++) {
        chiSquared += ((observed[i] - expected[i]) * (observed[i] - expected[i])) / expected[i];
    }
    return chiSquared;
}

int findBestKey(double observed[], double expected[]) {
    int bestKey = 0;
    double minChiSquared = FLT_MAX;

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
    //char* result_the = strstr(plaintext, " THE ");
    //char* result_alice = strstr(plaintext, " ALICE ");
    if(getNumberWordsFromDict(plaintext) > 400) {
      for (int i = 0; i < possible_key; i++) {
        free(cipher_groups[i]);
      }
      free(cipher_groups);
      break;
    }
    /*if(result_the != NULL && result_alice != NULL) { // Free Allocated Data and Break Loop (Key + Plaintext Found)
      for (int i = 0; i < possible_key; i++) {
        free(cipher_groups[i]);
      }
      free(cipher_groups);
      break;
    }*/
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

// Function to check if a key is in the failed keys set
int isKeyInFailedSet(char *key, char failedKeys[MAX_FAILED_KEYS][27], int numFailedKeys) {
    for (int i = 0; i < numFailedKeys; i++) {
        if (strcmp(key, failedKeys[i]) == 0) {
            return 1; // Key is in the failed set
        }
    }
    return 0; // Key is not in the failed set
}

// Function to add a key to the failed keys set
void addToFailedKeys(char *key, char failedKeys[MAX_FAILED_KEYS][27], int *numFailedKeys) {
    if (*numFailedKeys < MAX_FAILED_KEYS) {
        strcpy(failedKeys[*numFailedKeys], key);
        (*numFailedKeys)++;
    }
}

// Function to count number of words in ciphertext
int countWords(const char *text) {
  int count = 0;
  while (*text != '\0') {
    if (isspace(*text)) {
      count++;
    }
    text++;
  }
  return count + 1;
}

// Function to calculate bigram frequency
void calculateBigramFrequencies(char *text, double bigramFrequencies[ALPHABET_SIZE][ALPHABET_SIZE]) {
    int totalBigrams = 0;

    for (int i = 0; text[i] != '\0' && text[i + 1] != '\0'; i++) {
        if (isalpha(text[i]) && isalpha(text[i + 1])) {
            char first = toupper(text[i]);
            char second = toupper(text[i + 1]);

            bigramFrequencies[first - 'A'][second - 'A']++;
            totalBigrams++;
        }
    }
    //printf("BIGRAM TOTAL: %d\n", totalBigrams);
    // Convert counts to frequencies
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        for (int j = 0; j < ALPHABET_SIZE; j++) {
            //printf("%d\n", totalBigrams);
            bigramFrequencies[i][j] /= (double)totalBigrams;
            //printf("FREQ: %f\n", bigramFrequencies[i][j]);
        }
    }
}

// Function to calculate trigram frequencies
void calculateTrigramFrequencies(char *text, double trigramFrequencies[ALPHABET_SIZE][ALPHABET_SIZE][ALPHABET_SIZE]) {
    int totalTrigrams = 0;

    for (int i = 0; text[i] != '\0' && text[i + 1] != '\0' && text[i + 2] != '\0'; i++) {
        if (isalpha(text[i]) && isalpha(text[i + 1]) && isalpha(text[i + 2])) {
            char first = toupper(text[i]);
            char second = toupper(text[i + 1]);
            char third = toupper(text[i + 2]);

            trigramFrequencies[first - 'A'][second - 'A'][third - 'A']++;
            totalTrigrams++;
        }
    }

    // Convert counts to frequencies
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        for (int j = 0; j < ALPHABET_SIZE; j++) {
            for (int k = 0; k < ALPHABET_SIZE; k++) {
                trigramFrequencies[i][j][k] /= (double)totalTrigrams;
            }
        }
    }
}

struct LetterMatching {
  char self;       // Alphabet Character
  char match;      // Matching character in ciphertext
  double distance; // Estimated distance between two characters; Approaching 0 --> Better Match
};

int cs642PerformSUBSCryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, char *key) {
  // Calculate Letter Frequencies in Ciphertext
  struct LetterFrequency observed_letter_frequencies[ALPHABET_SIZE];
  for(int i = 0; i < ALPHABET_SIZE; i++) {
    observed_letter_frequencies[i].letter = i + 'A';
  }
  int total_chars = 0;
  for(int i = 0; ciphertext[i] != '\0'; i++) {
    if (isalpha(ciphertext[i])) {
      char temp = toupper(ciphertext[i]); // Convert to uppercase
      observed_letter_frequencies[temp - 'A'].frequency++; // Count letter occurrence
      total_chars++; // Increment total number of characters
    }
  }

  // Convert Counts to Frequencies
  for(int i = 0; i < ALPHABET_SIZE; i++) {
    observed_letter_frequencies[i].frequency = observed_letter_frequencies[i].frequency / (double)total_chars;
  }

  // Create Local Copy of Letter Frequencies
  struct LetterFrequency my_letter_frequencies[ALPHABET_SIZE];
  for(int i = 0; i < ALPHABET_SIZE; i++) {
    my_letter_frequencies[i].letter = letter_frequencies_struct[i].letter;
    my_letter_frequencies[i].frequency = letter_frequencies_struct[i].frequency;
  }

  // Rearrange Alphabets by Expected Frequencies (Most Frequent --> Least)
  qsort(my_letter_frequencies, ALPHABET_SIZE, sizeof(struct LetterFrequency), compareLetterFrequencies);
  qsort(observed_letter_frequencies, ALPHABET_SIZE, sizeof(struct LetterFrequency), compareLetterFrequencies);

  // Calculate Bigram Frequencies in Ciphertext
  double observed_bigram_frequencies[ALPHABET_SIZE][ALPHABET_SIZE] = {0};
  calculateBigramFrequencies(ciphertext, observed_bigram_frequencies);

  // Calculate Trigram Frequencies in Ciphertext
  double observed_trigram_frequencies[ALPHABET_SIZE][ALPHABET_SIZE][ALPHABET_SIZE] = {0};
  calculateTrigramFrequencies(ciphertext, observed_trigram_frequencies);

  // Sort Bigram Frequencies in Descending Order
  struct BigramFrequency observed_bigram_array[ALPHABET_SIZE * ALPHABET_SIZE];
  int index = 0;
  for (int i = 0; i < ALPHABET_SIZE; i++) {
    for (int j = 0; j < ALPHABET_SIZE; j++) {
      // Create a bigram string (2 characters plus null terminator)
      char bigram[3] = {i + 'A', j + 'A', '\0'};
            
      // Populate the struct
      strcpy(observed_bigram_array[index].bigram, bigram);
      observed_bigram_array[index].frequency = observed_bigram_frequencies[i][j];

      // Move to the next index
      index++;
    }
  }
  qsort(observed_bigram_array, ALPHABET_SIZE * ALPHABET_SIZE, sizeof(struct BigramFrequency), compareBigramFrequencies);

  // Sort Trigram Frequencies in Descending Order
  struct TrigramFrequency observed_trigram_array[ALPHABET_SIZE * ALPHABET_SIZE * ALPHABET_SIZE];
  index = 0;
  for (int i = 0; i < ALPHABET_SIZE; i++) {
    for (int j = 0; j < ALPHABET_SIZE; j++) {
      for (int k = 0; k < ALPHABET_SIZE; k++) {
        // Create a trigram string (3 characters plus null terminator)
        char trigram[4] = {i + 'A', j + 'A', k + 'A', '\0'};
              
        // Populate the struct
        strcpy(observed_trigram_array[index].trigram, trigram);
        observed_trigram_array[index].frequency = observed_trigram_frequencies[i][j][k];

        // Move to the next index
        index++;
      }
    }
  }
  qsort(observed_trigram_array, ALPHABET_SIZE * ALPHABET_SIZE * ALPHABET_SIZE, sizeof(struct TrigramFrequency), compareTrigramFrequencies);

  /*
  // Display Sorted Bigrams By Frequency
  for (int i = 0; i < ALPHABET_SIZE * ALPHABET_SIZE; i++) {
    printf("Bigram: %s; Frequency: %f\n", observed_bigram_array[i].bigram, observed_bigram_array[i].frequency);
  }

  // Display Sorted Trigrams By Frequency
  for (int i = 0; i < ALPHABET_SIZE * ALPHABET_SIZE * ALPHABET_SIZE; i++) {
    printf("Trigram: %s; Frequency: %f\n", observed_trigram_array[i].trigram, observed_trigram_array[i].frequency);
  }
  */

  // Create initial letter matching from monogram frequencies
  int num_matches = 0;
  struct LetterMatching matching[26];
  for(int i = 0; i < ALPHABET_SIZE; i++) {
    matching[i].self = my_letter_frequencies[i].letter;
    matching[i].match = observed_letter_frequencies[i].letter;
    double distance = fabs(my_letter_frequencies[i].frequency - observed_letter_frequencies[i].frequency);
    if(distance < 0.0019) {
      matching[i].distance = distance;
      num_matches++;
      //printf("%c: %c\n", matching[i].self, matching[i].match);
    }
    matching[i].distance = distance;
  }

  // Construct key from current matching
  char best_key[ALPHABET_SIZE + 1];

  char curr_letter = 'A';
  while (curr_letter <= 'Z') {
    int curr_index = 0;
    // Find the index of the current letter in the observed alphabet
    while (matching[curr_index].self != curr_letter) {
      curr_index++;
    }
    // Map the observed letter to the key
    best_key[curr_letter - 'A'] = matching[curr_index].match;
    curr_letter++;
  }
  best_key[ALPHABET_SIZE] = '\0';
  cs642Decrypt(CIPHER_SUBS, best_key, 26, plaintext, plen, ciphertext, clen);
  
  // Loop Variables
  // Initialize variables to keep track of failed keys
  char failedKeys[MAX_FAILED_KEYS][27];
  int numFailedKeys = 0;

  // Attempt Various Key Possibilities
  int attempts = 0;
  //int key_attempts = 0;
  int bestNumber = getNumberWordsFromDict(plaintext);
  int increment_distance = 0;
  int updates = 0;
  printf("KEY: %s SIMILARITY: %d\n", best_key, bestNumber);

  // Utilize the initial matching to pseudo-randomly form keys from individual letter frequencies
  while(bestNumber < 450 && attempts < MAX_ATTEMPTS * 3) {
    for(int i = 0; i < 26 - 1; i++) {
      double max_freq = observed_letter_frequencies[i].frequency;
      int max_freq_idx = i;
      // Find largest char-frequency pair from i-26
      for(int j = i + 1; j < 26; j++) {
        if(observed_letter_frequencies[j].frequency > max_freq || (fabs(observed_letter_frequencies[j].frequency - max_freq) <= 0.001 + (0.001 * increment_distance) && rand() % 2 == 0)) { // Arbitrarily swap similar frequency characters
          max_freq = observed_letter_frequencies[j].frequency;
          max_freq_idx = j;
        }
      }
      
      // Swap found largest frequency to ith position
      double temp_freq = observed_letter_frequencies[i].frequency;
      double temp_letter = observed_letter_frequencies[i].letter;
      observed_letter_frequencies[i].frequency = max_freq;
      observed_letter_frequencies[i].letter = observed_letter_frequencies[max_freq_idx].letter;
      observed_letter_frequencies[max_freq_idx].frequency = temp_freq;
      observed_letter_frequencies[max_freq_idx].letter = temp_letter;
    }

    // Form New Matching With Rearranged Expected Frequencies
    struct LetterMatching new_matching[26];
    for(int i = 0; i < ALPHABET_SIZE; i++) {
      new_matching[i].self = my_letter_frequencies[i].letter;
      new_matching[i].match = observed_letter_frequencies[i].letter;
      double distance = fabs(my_letter_frequencies[i].frequency - observed_letter_frequencies[i].frequency);
      new_matching[i].distance = distance;
    }

    // Form New Key From New Matching
    char new_key[ALPHABET_SIZE + 1];

    char curr_letter = 'A';
    while (curr_letter <= 'Z') {
      int curr_index = 0;
      // Find the index of the current letter in the observed alphabet
      while (new_matching[curr_index].self != curr_letter) {
        curr_index++;
      }
      // Map the observed letter to the key
      new_key[curr_letter - 'A'] = new_matching[curr_index].match;
      curr_letter++;
    }
    new_key[ALPHABET_SIZE] = '\0';

    // Update the best key if the current attempt is better
    //printf("NEW KEY: %s\n", new_key);
    cs642Decrypt(CIPHER_SUBS, new_key, 26, plaintext, plen, ciphertext, clen);
    int currentNumber = getNumberWordsFromDict(plaintext);

    //printf("NEW KEY: %s SIMILARITY: %d\n", new_key, currentNumber);
    if (currentNumber > bestNumber) {
      // Update Best Number and Key
      bestNumber = currentNumber;
      strcpy(best_key, new_key);

      // Update Matches
      for(int i = 0; i < ALPHABET_SIZE; i++) {
        matching[i].distance = new_matching[i].distance;
        matching[i].self = new_matching[i].self;
        matching[i].match = new_matching[i].match;
      }

      // Increment Updates
      updates++;
    }
    else { // Attempt Not Better --> Add to Failed Keys
      addToFailedKeys(key, failedKeys, &numFailedKeys);
    }
    //printf("BEST KEY: %s SIMILARITY: %d\n", best_key, bestNumber);
    //cs642Decrypt(CIPHER_SUBS, best_key, 26, plaintext, plen, ciphertext, clen);
    attempts++;
  }

  printf("ATTEMPTS: %d\n", attempts);
  printf("UPDATES: %d\n", updates);
  printf("KEY: %s SIMILARITY: %d\n", best_key, bestNumber);

  // Reset Attempts and Updates
  updates = 0;
  attempts = 0;

  /**** BIGRAM LOGIC ****/
  // Match Letters By Bigram Frequency
  while(bestNumber < 450 && attempts < MAX_ATTEMPTS) {
    // For each unmatched character
    for(int curr_idx = 0; curr_idx < ALPHABET_SIZE; curr_idx++) {
      //printf("BEST KEY: %s SIMILARITY: %d\n", best_key, bestNumber);
      //printf("INCREMENT DISTANCE: %d\n", increment_distance);
      //printf("SELF: %c DISTANCE: %f\n", matching[curr_idx].self, matching[curr_idx].distance);
      if(matching[curr_idx].distance > 0.0019 + (0.001 * increment_distance)) { // If character uunmatched, traverse bigrams
        //printf("HELLO\n");
        for(int i = 0; observed_bigram_array[i].frequency > 0; i++) { 
          //printf("%d\n", i);
          // Find bigrams to which character belongs and get other letter
          char paired_letter;  // Stores paired letter of bigram
          int bigram_idx = -1; // Tracks location of letter in bigram
          if(matching[curr_idx].self == observed_bigram_array[i].bigram[0]) {
            paired_letter = observed_bigram_array[i].bigram[1];
            bigram_idx = 0;
          } 
          else if (matching[curr_idx].self == observed_bigram_array[i].bigram[1]) {
            paired_letter = observed_bigram_array[i].bigram[0];
            bigram_idx = 1;
          }

          // Get matching information of paired letter
          int pair_idx = -1;
          for(int j = 0; j < ALPHABET_SIZE; j++) {
            if(matching[j].self == paired_letter) {
              pair_idx = j;
              break;
            }
          }

          // Construct Key Candidate
          char new_key[ALPHABET_SIZE + 1];
          strcpy(new_key, best_key);
          int swap_idx = 0;
          double freq_of_bigram = 0;
          //printf("NEW KEY: %s \n", new_key);

          // Check if paired letter matched
          if(matching[pair_idx].distance < 0.0019 + (0.001 * increment_distance)) { // Paired matched --> set letter to correspond
            // Get new letter to match
            char new_match = bigramArray[i].bigram[bigram_idx];
            freq_of_bigram = bigramArray[i].frequency;
            // Find letter currently matching to the new match and swap in key with current letter
            for(int j = 0; j < ALPHABET_SIZE; j++) {
              if(matching[j].match == new_match) {
                swap_idx = j;
                break;
              }
            }
            // Swap Only in Key
            new_key[matching[curr_idx].self - 'A'] = matching[swap_idx].match;
            new_key[matching[swap_idx].self - 'A'] = matching[curr_idx].match;
          }
          //printf("NEW KEY: %s \n", new_key);

          /*char curr_letter = 'A';
          while (curr_letter <= 'Z') {
            int curr_index = 0;
            // Find the index of the current letter in the observed alphabet
            while (matching[curr_index].self != curr_letter) {
              curr_index++;
            }
            // Map the observed letter to the key
            //key[curr_letter - 'A'] = matching[curr_index].match;
            new_key[curr_letter - 'A'] = matching[curr_index].match;
            curr_letter++;
          }
          new_key[ALPHABET_SIZE] = '\0';*/

          // Skip this attempt and generate a new key
          if (isKeyInFailedSet(new_key, failedKeys, numFailedKeys)) {
            continue;
          }

          // Update the best key if the current attempt is better
          cs642Decrypt(CIPHER_SUBS, new_key, 26, plaintext, plen, ciphertext, clen);
          //printf("%d %f: PLAIN: %s\n", attempts, getPercentageWordsFromDict(plaintext), plaintext);
          int currentNumber = getNumberWordsFromDict(plaintext);
          //printf("NEW KEY: %s SIMILARITY: %d\n", new_key, currentNumber);
          if (currentNumber > bestNumber) {
            // Update Best Number and Key
            bestNumber = currentNumber;
            strcpy(best_key, new_key);

            // Retain Swap in Struct
            char temp = matching[curr_idx].match;
            matching[curr_idx].match = matching[swap_idx].match;
            matching[swap_idx].match = temp;

            double temp_dist = matching[curr_idx].distance;
            matching[curr_idx].distance = matching[swap_idx].distance * freq_of_bigram;
            //matching[swap_idx].distance = temp_dist * freq_of_bigram;
            matching[swap_idx].distance = temp_dist;

            matching[pair_idx].distance = matching[pair_idx].distance * freq_of_bigram;
            // Increment Updates
            updates++;
          }
          // Attempt Not Better --> Add to Failed Keys
          else {
            addToFailedKeys(key, failedKeys, &numFailedKeys);
          }
          //printf("BEST KEY: %s SIMILARITY: %d\n", best_key, bestNumber);
        }
      }
    }
    increment_distance++; // Increase matching threshold (be stricter on matches)
    attempts++;
  }
  printf("ATTEMPTS: %d\n", attempts);
  printf("UPDATES: %d\n", updates);
  printf("KEY: %s SIMILARITY: %d\n", best_key, bestNumber);

  // Reset Attempts and Updates
  updates = 0;
  attempts = 0;
  increment_distance = 0;

  /**** TRIGRAM LOGIC ****/
  while (bestNumber < 450 && attempts < MAX_ATTEMPTS) {
      // For each unmatched character
      for (int curr_idx = 0; curr_idx < ALPHABET_SIZE; curr_idx++) {
          if (matching[curr_idx].distance > 0.0019 + (0.001 * increment_distance)) { // If character unmatched, traverse trigrams
              for (int i = 0; observed_trigram_array[i].frequency > 0; i++) {
                  // Find trigrams to which character belongs
                  char paired_letters[2];  // Stores paired letters of trigram
                  int trigram_idx = -1; // Tracks location of letter in trigram
                  if (matching[curr_idx].self == observed_trigram_array[i].trigram[0]) {
                      paired_letters[0] = observed_trigram_array[i].trigram[1];
                      paired_letters[1] = observed_trigram_array[i].trigram[2];
                      trigram_idx = 0;
                  } 
                  else if (matching[curr_idx].self == observed_trigram_array[i].trigram[1]) {
                      paired_letters[0] = observed_trigram_array[i].trigram[0];
                      paired_letters[1] = observed_trigram_array[i].trigram[2];
                      trigram_idx = 1;
                  } 
                  else if (matching[curr_idx].self == observed_trigram_array[i].trigram[2]) {
                      paired_letters[0] = observed_trigram_array[i].trigram[0];
                      paired_letters[1] = observed_trigram_array[i].trigram[1];
                      trigram_idx = 2;
                  }

                  // Get matching information of paired letters
                  int pair_indices[2] = {-1, -1};
                  for (int j = 0; j < ALPHABET_SIZE; j++) {
                      if (matching[j].self == paired_letters[0]) {
                          pair_indices[0] = j;
                      }
                      if (matching[j].self == paired_letters[1]) {
                          pair_indices[1] = j;
                      }
                      if (pair_indices[0] != -1 && pair_indices[1] != -1) {
                          break;
                      }
                  }

                  // Construct Key Candidate
                  char new_key[ALPHABET_SIZE + 1];
                  strcpy(new_key, best_key);
                  int swap_idx = 0;
                  double freq_of_trigram = 0;

                  // Check if paired letters matched and if the frequency is significant
                  if (matching[pair_indices[0]].distance < 0.0019 + (0.001 * increment_distance) &&
                      matching[pair_indices[1]].distance < 0.0019 + (0.001 * increment_distance)) {
                      // Get new letter to match
                      char new_match = trigramArray[i].trigram[trigram_idx];
                      freq_of_trigram = trigramArray[i].frequency;

                      for(int j = 0; j < ALPHABET_SIZE; j++) {
                        if(matching[j].match == new_match) {
                          swap_idx = j;
                          break;
                        }
                      }
                      // Swap Only in Key
                      new_key[matching[curr_idx].self - 'A'] = matching[swap_idx].match;
                      new_key[matching[swap_idx].self - 'A'] = matching[curr_idx].match;
                      // Skip this attempt and generate a new key
                      if (isKeyInFailedSet(new_key, failedKeys, numFailedKeys)) {
                        continue;
                      }

                      // Update the best key if the current attempt is better
                      cs642Decrypt(CIPHER_SUBS, new_key, 26, plaintext, plen, ciphertext, clen);
                      int currentNumber = getNumberWordsFromDict(plaintext);
                      //printf("NEW KEY: %s SIMILARITY: %d\n", new_key, currentNumber);
                      if (currentNumber > bestNumber) {
                          // Update Best Number and Key
                          bestNumber = currentNumber;
                          strcpy(best_key, new_key);

                          // Retain Swap in Struct
                          char temp = matching[curr_idx].match;
                          matching[curr_idx].match = matching[swap_idx].match;
                          matching[swap_idx].match = temp;

                          double temp_dist = matching[curr_idx].distance;
                          matching[curr_idx].distance = matching[swap_idx].distance * freq_of_trigram;
                          //matching[swap_idx].distance = temp_dist * freq_of_bigram;
                          matching[swap_idx].distance = temp_dist;

                          matching[pair_indices[0]].distance = matching[pair_indices[0]].distance * freq_of_trigram;
                          matching[pair_indices[1]].distance = matching[pair_indices[1]].distance * freq_of_trigram;

                          // Increment Updates
                          updates++;
                      } else {
                          // Attempt Not Better --> Add to Failed Keys
                          addToFailedKeys(key, failedKeys, &numFailedKeys);
                      }
                  }
              }
          }
      }
      increment_distance++; // Increase matching threshold (be stricter on matches)
      attempts++;
  }
  printf("ATTEMPTS: %d\n", attempts);
  printf("UPDATES: %d\n", updates);
  printf("KEY: %s SIMILARITY: %d\n", best_key, bestNumber);
  cs642Decrypt(CIPHER_SUBS, best_key, 26, plaintext, plen, ciphertext, clen);

  strcpy(key, best_key);
  // Return success
  return 1;
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