////////////////////////////////////////////////////////////////////////////////
//
//  File           : cs642-cryptanalysis-support.h
//  Description    : This is an include file to define structures and support
//                   functions for the cryptanalysis project.
//
//   Author        : Patrick McDaniel
//   Last Modified : Sun Sep 24 14:14:35 UTC 2023

// Include Files
#include <stdint.h>

//
// Type definitions

// Ciphers used in this assignment
typedef enum {
  CIPHER_ROTX = 0, // ROT-X Cipher
  CIPHER_VIGE = 1, // Vigenere Cipher
  CIPHER_SUBS = 2, // Substitution Cipher
  CIPHER_UNK = 3,  // Unknown cipher
  CIPHER_MAX = 4   // Maximum number of ciphers
} cs642Cipher;

// Define struct and type for dictionary
struct DictWord {
  char *word; // String
  int count;  // Nunber of times it appears in text corpus
};
typedef struct DictWord DictWord;

//
// External declarations

extern const char *cs642CipherStrings[];
// The cipher strings for printing

extern uint32_t CipherVerboseLevel;
// Log level for the ciphers

extern int cs642Verbose;
// Verbose flag

//
// Support functions

int cs642Encrypt(cs642Cipher cip, char *key, int keylen, char *ptext, int plen,
                 char *ctext, int clen);
// This function encrypts the data using the key and cipher

int cs642Decrypt(cs642Cipher cip, char *key, int keylen, char *ptext, int plen,
                 char *ctext, int clen);
// This function decrypts the data using the key and cipher

DictWord cs642GetWordfromDict(int idx);
// Get a word from the dictionary (by its index)

int cs642GetDictSize(void);
// Get the number of words in the dictionary

int cs642GetCipherKeyLength(cs642Cipher cipher);
// Get the key length for the cipher

//
// Utility Functions (NOT TO BE CALLED BY STUDENTS)
int cs642StartProject(void);
// initialize required datastructures for project

char *cs642GetCiphertextSample(cs642Cipher cipher);
// get a sample of ciphertext at random

int cs642CheckPlaintext(cs642Cipher cipher, char *plaintext, char *ciphertext,
                        char *key);
// Check the plaintext and key for a cipher test

int cs642CipherUnittest(void);
// This function tests all of the ciphers

int cs642CleanCipherStructures(void);
// cleanup all of the plaintext file structures
