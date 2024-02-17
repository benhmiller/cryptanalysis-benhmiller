# Project 1 - Cryptanalysis - COMP SCI 642: Introduction to Information Security - Spring 2024 - Prof. Cecchetti 

## Due date: Friday, March 8th, 2024 - 11:59pm CDT


## Description

In this project, you will perform cryptanalysis on some ciphertexts. Your
objective is to build automated tools to break these ciphers, information about
them will be provided to help you in your task.

Please follow the instructions carefully and turn in the results as directed
before the deadline above.

## Dependencies and cloning instructions

To execute this project, you have 2 options:
1. Using Docker (works on all architectures).
2. Using a GNU/Linux VM (known issues with VirtualBox support for M1/M2 Macs
   though).

### Using Docker (works on all architectures)

**Note:** skip the use of Docker if you are using the VM option.

- Install [Docker](https://docs.docker.com/engine/install/) and
  [git](https://git-scm.com/downloads) on your machine. If you are a macOS user,
  you should also authorize Docker to access your files, see this
  [guide](https://support.apple.com/en-gb/guide/mac-help/mchld5a35146/mac).

- Configure git on your machine and optionally [add a SSH key to your GitHub
  account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/about-ssh):
    ```sh
    git config --global user.name "Bucky Badger"
    git config --global user.email uw-bucky-badger@wisc.edu
    ```

- Accept the GitHub Classroom link provided on the Canvas Assignment, a private
  GitHub repository is created for you, clone it on your machine (you can find the
  HTTPS or SSH url by clicking on the green button named *Code*):

    `git clone <HTTPS_OR_SSH_URL>UW-Madison-COMPSCI642/cryptanalysis-<YOUR_GITHUB_USERNAME>.git`

- A `Dockerfile` is provided under `.devcontainer/` (for direct integration with
VS Code). Using VS Code with Docker and VS Code Dev Containers extension as
described on [this
guide](https://gist.github.com/yohhaan/b492e165b77a84d9f8299038d21ae2c9) will
likely be the easiest for you. If you have issues with sharing the git
credentials with your Docker container, refer to this
[documentation](https://code.visualstudio.com/remote/advancedcontainers/sharing-git-credentials).

- In case, you would like to manually build the image and deploy the Docker
container to test your code (if you are not using VS Code but another
development workflow), follow the instructions below:

  1. Build the Docker image (needs to be done only once normally):
    ```sh
    docker build -t cs642-cryptanalysis-docker-image .devcontainer/
    ```

  2. Every time you want to test your code and if you have exited the container
     you had previously created, you will have to deploy a new Docker container:
    ```sh
    docker run --rm -it -v ${PWD}:/workspace/cryptanalysis \
        -v ${HOME}/.gitconfig:/home/vscode/.gitconfig \
        -v ${HOME}/.ssh:/home/vscode/.ssh \
        -w /workspace/cryptanalysis \
        --entrypoint bash cs642-cryptanalysis-docker-image:latest
    ```
    Note: you may have to edit the source path for the `.gitconfig` and `.ssh`
    volumes (for now it looks for those in your home directory on your machine).
    These 2 volumes are needed so that your git configurations and potential ssh
    keys are accessible from within the Docker container, respectively.

- You are ready to start on your project! It is highly recommended to keep track
  of your modifications often by committing and pushing your changes to your
  private repository.

### Using a GNU/Linux VM (known issues with VirtualBox support for M1/M2 Macs though)

**Note:** skip the use of a VM if you are using the Docker option.

- Deploy a GNU/Linux VM (we recommend `Ubuntu 22.04 LTS`).

- Follow the instructions on the Canvas course page to create this VM.

- Login into your VM, open a terminal, and install the following dependencies:
    `sudo apt-get update && sudo apt-get -y install build-essential gcc gdb git
    libcurl4-gnutls-dev libgcrypt20-dev valgrind gnupg2 openssh-client ca-certificates`

- Configure git on your VM and optionally [add a SSH key to your GitHub
  account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/about-ssh):
    ```sh
    git config --global user.name "Bucky Badger"
    git config --global user.email uw-bucky-badger@wisc.edu
    ```

- Accept the GitHub Classroom link provided on the Canvas Assignment, a private
  GitHub repository is created for you, clone it on your VM (you can find the
  HTTPS or SSH url by clicking on the green button named *Code*):

    `git clone <HTTPS_OR_SSH_URL>UW-Madison-COMPSCI642/cryptanalysis-<YOUR_GITHUB_USERNAME>.git`

- You are ready to start on your project! It is highly recommended to keep track
  of your modifications often by committing and pushing your changes to your
  private repository.

## Project Details

The environment contains several libraries, source code files, and other
supporting data. The only file you will need to edit for this assignment is
`cs642-cryptanalysis-impl.c`. To build the project, you will need to run the
`make` utility with no arguments.

The functions you will implement (in `cs642-cryptanalysis-impl.c`) are
called `cs642PerformROTXCryptanalysis`, `cs642PerformVIGECryptanalysis`, and `cs642PerformSUBSCryptanalysis`, each of which receives 5 parameters, as
described here:

- `ciphertext` - the ciphertext to break
- `clen` - the length of the ciphertext
- `plaintext` - a string for you to place the plaintext once you have broken the
  cipher
- `plen` - the length of the plaintext
- `key` - a place to put the key (this value will be large enough to put the key
in it as described in the following table).

### The ciphers you will operate on are:

| Cipher              | Key                  | Values                         |
| ------------------- | -------------------- | ------------------------------ |
| X-rotation (ROTX)   | uint8_t              | 1-25                           |
| Vigenere (VIGE)     | string of characters | 6-11                           |
| Substitution (SUBS) | char[26]             | substitution values (a=0, b=1) |

The `ciphertext` consists of uppercase letters (only) and spaces. You are to
recover the plaintext of the original (unencrypted) text and place that in the
`plaintext` string passed to the function, as well as place the key in the
associated variable `key`.  Once you have completed this, return a value of 0
and the program will automatically check the result.

### Some notes on the ciphers:

**ROTX**: The rotation-X cipher performs encryption by rotating the letter of
the ciphertext *X* letters to the right (and wrapping around), and decryption is
done by rotating the letter *X* letters to the left (and wrapping around). *X*
is the key.

**VIGE**: The key is a string of a length of 6-11 characters.  This cipher works
by rotating the first character by *n* letters to the right, where *n* is
indicated by the letter in the first position (i.e., 'A' rotates 1, 'B' rotates
2, ..., 'Z' rotates 26).  The second character rotates in the second position,
third in the third, etc. Note that spaces count in terms of position, you just
don't rotate.

**SUBS**: This cipher operates by creating a random permutation of the alphabet,
where each character is replaced by another during encryption and switched back
during decryption. The key is the permutation, where position 0 is the
character that replaces 'A' in the plaintext, position 1 replaces 'B', etc.

For this project, you will have to figure out the key and recover the plaintext.
This will require two operations. First you will have to perform the
cryptanalysis of the key using the techniques we discussed in class. Then, once
you have recovered the key, you will have to obtain the plaintext. You can use
the following functions (already coded for you) that implement the ciphers
discussed in class (hint: you will probably only need decrypt).

```c
int cs642Encrypt( cs642Cipher cip, char *key, int keylen, char *ptext, int plen, char *ctext, int clen );

int cs642Decrypt( cs642Cipher cip, char *key, int keylen, char *ptext, int plen, char *ctext, int clen );
```

To further help with this process, two functions are provided to access the list
of all possible words appearing in the plaintext:
- `int cs642GetDictSize( void );` will tell you how many total words are in the
dictionary.
- `DictWord cs642GetWordfromDict( int idx );` will return a `DictWord` struct
that contains a pointer to the string of each word as well as the number of
times the word appears in the text corpus. This function can be really helpful
to figure out if you have correctly recovered the key and plaintext, once you
have performed the cryptanalysis.

### Student Init and Clean Up Functions

Depending on your implementation, you may decide to build some data structures
that will be reused in the cryptanalysis of the different ciphers. If so, use
the `cs642StudentInit(void)` and `cs642StudentCleanUp(void)` functions to
initialize and clean up these data structures, they are called before the
cryptanalysis starts and after it is completed, respectively.

Note: you may not need to use these functions, if so, leave them as they are.


### How to compile, test, and debug

Use the provided [`Makefile`](Makefile):
- To clean your compiled objects, run `make clean`
- To execute your program, run `make`
- To execute your program with verbose mode, run `make test`
- To debug your program with `gdb` run `make debug`
- To debug your program with `valgrind` run `make memdebug`

If your program completes successfully, you should get:
   ```
   *** All Cryptanalysis succeeded, assignment complete!!! ***.
   ```

## How to turn in

1. Commit and push your changes to the private repository created by GitHub
   Classroom before the deadline.

2. **And** submit on Canvas before the deadline both your *GitHub username* and
   the *commit ID* that should be graded. Otherwise, you will receive a 0 for
   the assignment. Note that the TA will grade your repository as available at:
   `https://github.com/UW-Madison-COMPSCI642/cryptanalysis-<YOUR_GITHUB_USERNAME>/commit/<COMMIT_ID_TO_GRADE>`

**Tip:** you can test that the TA will obtain the correct version of your code and
that they will be able to compile it by:

- Cloning again your GitHub repository into *another* location on your machine
  or VM.

    `git clone <HTTPS_OR_SSH_URL>UW-Madison-COMPSCI642/cryptanalysis-<YOUR_GITHUB_USERNAME>.git`

- Checking out to the commit ID you would like to be graded.

    `git checkout <COMMIT_ID_TO_GRADE>`

- Compiling your code and testing that everything works as expected.

    `make test`


## Note

**Like all assignments in this class you are prohibited from copying any content
from the Internet or discussing, sharing ideas, code, configuration, text or
anything else or getting help from anyone in or outside of the class. Consulting
online sources is acceptable, but under no circumstances should *anything* be
copied. Failure to abide by this requirement will result dismissal from the
class as described in the course syllabus on Canvas.**
