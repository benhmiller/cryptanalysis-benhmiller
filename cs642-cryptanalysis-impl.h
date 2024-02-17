////////////////////////////////////////////////////////////////////////////////
//
//  File           : cs642-cryptanalysis-impl.h
//  Description    : This is an include file to define cryptanalysis
//                   functions for the cryptanalysis project.
//
//   Author        : Patrick McDaniel
//   Last Modified : Mon Oct  2 20:46:44 UTC 2023

// Include Files

//
// Implementation functions

int cs642StudentInit(void);
// This is a function that is called before any cryptanalysis occurs. Use it if
// you need to initialize some datastructures you may be reusing across ciphers.

int cs642PerformROTXCryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, uint8_t *key);
// This is the function to cryptanalyze the ROT X cipher

int cs642PerformVIGECryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, char *key);
// This is the function to cryptanalyze the Vigenere cipher

int cs642PerformSUBSCryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, char *key);
// This is the function to cryptanalyze the substitution cipher

int cs642StudentCleanUp(void);
// This is a clean up function called at the end of the cryptanalysis of the
// different ciphers. Use it if you need to release  memory you allocated in
// cs642StudentInit() for instance.
