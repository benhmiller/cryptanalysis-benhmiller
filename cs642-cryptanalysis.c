////////////////////////////////////////////////////////////////////////////////
//
//  File           : cs642-cryptanalysis.c
//  Description    : This is the main program for the cs642 first project that
//                   performs cryptanalysis on ciphertext of different ciphers.
//
//   Author        : Patrick McDaniel
//   Last Modified : Sun Sep 24 14:13:20 UTC 2023

// Include Files
#include <compsci642_log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Project Include Files
#include "cs642-cryptanalysis-impl.h"
#include "cs642-cryptanalysis-support.h"

// Defines
#define cs642_CRYPTANALYSIS_ARGUMENTS "vuh"
#define cs642_CRYPTANALYSIS_USAGE                                              \
  "\n"                                                                         \
  "  cryptanalysis -c <cipher> [-v] [-u] [-h]\n\n"                             \
  "  where:\n"                                                                 \
  "     -u - runs the unit test (no cipher needed)\n"                          \
  "     -v - verbose mode (display all logging messages)\n"                    \
  "     -h - displays this help message, and returns\n\n"
#define CS642_CRYPTANALYSIS_TESTS 3

// This is the file table

//
// Global Data
int cs642Verbose = 0;
uint32_t CipherVerboseLevel;

//
// Functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : main
// Description  : The main function for the cryptanalysis program
//
// Inputs       : argc - the number of command line parameters
//                argv - the parameters
// Outputs      : 0 if successful test, -1 if failure

int main(int argc, char *argv[]) {

  // Local variables
  int ch, log_initialized = 0, unit_tests = 0, keylen, i, clen;
  char *ciphertext, *plaintext, *key;
  cs642Cipher cipher = CIPHER_UNK;

  // Process the command line parameters
  while ((ch = getopt(argc, argv, cs642_CRYPTANALYSIS_ARGUMENTS)) != -1) {
    switch (ch) {
    case 'v': // Verbose Flag
      cs642Verbose = 1;
      break;

    case 'u': // enable unit tests
      unit_tests = 1;
      break;

    case 'h': // Help Flag
      fprintf(stderr, cs642_CRYPTANALYSIS_USAGE);
      return (0);

    default: // Default (unknown)
      fprintf(stderr, "Unknown command line option (%c), aborting.\n", ch);
      return (-1);
    }
  }

  // Setup the log as needed
  if (!log_initialized) {
    initializeLogWithFilehandle(COMPSCI642_LOG_STDOUT);
  }
  CipherVerboseLevel =
      registerLogLevel("CipherVerboseLevel", 0); // Controller log level
  if (cs642Verbose) {
    enableLogLevels(LOG_INFO_LEVEL);
    enableLogLevels(CipherVerboseLevel);
  }

  // Run the unit tests
  if (unit_tests) {
    if (cs642CipherUnittest()) {
      fprintf(stderr, "Unit tests failed, aborting.\n");
      return (-1);
    }
  } else {

    // Run the cryptanalysis tests
    logMessage(LOG_OUTPUT_LEVEL,
               "*** Starting Cryptanalysis starting ... ***.");

    // initialize required datastructures for project
    cs642StartProject();

    if (cs642StudentInit()) {
      logMessage(LOG_ERROR_LEVEL, "cs642StudentInit failed, aborting program.");
      exit(-1);
    } else {
      logMessage(LOG_OUTPUT_LEVEL, "cs642StudentInit succeeded");
    }

    for (cipher = CIPHER_ROTX; cipher < CIPHER_UNK; cipher++) {
      for (i = 0; i < CS642_CRYPTANALYSIS_TESTS; i++) {

        // Get the ciphertext, create space for key and plaintext
        ciphertext = cs642GetCiphertextSample(cipher);
        clen = strlen(ciphertext);
        plaintext = malloc(clen + 1);
        memset(plaintext, 0x00, clen + 1);
        keylen = cs642GetCipherKeyLength(cipher);
        key = malloc(keylen + 1);
        memset(key, 0x00, keylen + 1);

        // Perform the cryptanalysis
        switch (cipher) {
        case CIPHER_ROTX:
          cs642PerformROTXCryptanalysis(ciphertext, clen, plaintext, clen,
                                        (uint8_t *)key);
          break;
        case CIPHER_VIGE:
          cs642PerformVIGECryptanalysis(ciphertext, clen, plaintext, clen, key);
          break;
        case CIPHER_SUBS:
          cs642PerformSUBSCryptanalysis(ciphertext, clen, plaintext, clen, key);
          break;
        default:
          logMessage(LOG_ERROR_LEVEL, "Unknown cipher (%d) in cryptanalysis.",
                     cipher);
          break;
        }

        // Now check result
        if (cs642CheckPlaintext(cipher, plaintext, ciphertext, key)) {
          logMessage(
              LOG_ERROR_LEVEL,
              "Cryptanalysis %d/%d failed for cipher (%s), aborting program.",
              i + 1, CS642_CRYPTANALYSIS_TESTS, cs642CipherStrings[cipher]);
          exit(-1);
        } else {
          logMessage(LOG_OUTPUT_LEVEL,
                     "Cryptanalysis %d/%d succeeded for cipher (%s).", i + 1,
                     CS642_CRYPTANALYSIS_TESTS, cs642CipherStrings[cipher]);
        }

        // Clean up the memory
        free(plaintext);
        plaintext = NULL;
        free(key);
        key = NULL;
        free(ciphertext);
        ciphertext = NULL;
      }
    }
    cs642CleanCipherStructures(); // Clean up the cipher structures
    if (cs642StudentCleanUp()) {
      logMessage(LOG_ERROR_LEVEL,
                 "cs642StudentCleanUp failed, aborting program.");
      exit(-1);
    } else {
      logMessage(LOG_OUTPUT_LEVEL, "cs642StudentCleanUp succeeded");
    }
    logMessage(LOG_OUTPUT_LEVEL,
               "*** All Cryptanalysis succeeded, assignment complete!!! ***.");
  }

  // Return successfully
  return (0);
}