/*******************************************************************************
 * @file parallel_search_keyspace.c
 * 
 * @brief Program demonstrates the use of pipes (ring of processes)
 * to brute-force search for an AES encryption key given a partial key.
 *  
 * @author Benjamin Nolan
 * Student ID: 220220586
 * Written in: C
 * @date 2022-07-17
 * @version 3.0
 * 
 * Parameters:
 *     1. The number of worker processes
 *     2. The partial key to use for the search
 * 
 * Build: 
 *    gcc -Wall -pedantic -lcrypto parallel_search_keyspace.c -o 
 * parallel_search_keyspace
 * 
 * Run Example:
 * psk 5 B1AF2507B69F11CCB3AE2C3592039
 * expected full key: B1AF2507B69F11CCB3AE2C35920395C3
 ******************************************************************************/

/**
 * Notes:
 * 16/07/2022 - Loops through every test key from Count 0 to 51
 * and TLB from 4121409605558682368 to 4121409605558682419 on partial key:
 * B1AF2507B69F11CCB3AE2C35920395C
 * on each child
 * But duplicates per child (maxspace of 255 equal to 51 searches replicated * j)
 * 
 * Created a version 2 that I am working on to do the following:
 * get each test key to be passed to each child instead.
 * 
 * 17/07/2022 - Managed to get the loop for counter modified to divide amongst 
 * processes.
 * 
 * Thought the keys were shared amongst child processes but they are not.
 * 
 * Managed to pass the keys into each child process.
 * 
 * initial processing time for 1 process with 3 chars to find in partial key
 * entered was 22 seconds
 * 2 processes halfed to just 12 seconds, followed by 8 for 3 and then 6 for 4.
 * 1 second reduction from 5+ processes.
 * 
 * Tested and working.
 */

/*******************************************************************************
 * Libraries
 ******************************************************************************/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <time.h>
/*******************************************************************************
* Static definitions
 ******************************************************************************/
#define PLAINTEXT "./plain.txt"
#define CIPHERTEXT "./assignment_cipher.txt"
#define BUFFER 1024 //total amount of contents to read from a file
#define MAX_KLEN 32 //total length of any given partial key
/*******************************************************************************
* Declarations
 ******************************************************************************/
int make_trivial_ring();
int add_new_node(int *pid);
int aes_init (unsigned char *kd, EVP_CIPHER_CTX * e_ctx, 
EVP_CIPHER_CTX * d_ctx);
unsigned char *aes_decrypt (EVP_CIPHER_CTX * e, unsigned char *ciphertext, 
int *len);
/******************************************************************************/


/*******************************************************************************
 * main
 * 
 * Parameters:
 *     1. The number of worker processes 
 *     2. The partial key to use for the search
 * 
 *     Cipher text and plain file path is specified at top
 *
*******************************************************************************/
int main (int argc, char *argv[]) {

    // argument checking
    if (argc != 3) { 
        fprintf (stderr, "Usage: %s <num processes> <partial key>\n", argv[0]);
        return (-1);
    }

    // setting number of processes into memory from passed argument
    int nodes = atoi(argv[1]); // num processes passed as arg 1
    
    // setting partial key into memory from passed argument
    unsigned char *kd; // pointer for partial key
    int kdlen; // length of partial key

    kd = (unsigned char *) argv[2]; // partial key to memory
    kdlen = strlen (argv[2]); // length of partial key passed as arg 2

    // make sure passed argument of key is not equal to a length of 32
    if ( kdlen >= 32 ) {
        fprintf(stderr,
        "Partial key must be less than %d in length, %d was entered.\n",
        MAX_KLEN,kdlen);
        exit(EXIT_FAILURE);
    }

    int plen; // length of plaintext contents
    int clen; // length of cipherfile contents

    // read cipher file into memory
    FILE *CFILE; // pointer for cipher text file
    CFILE = fopen (CIPHERTEXT,"r"); // open cipher text file
    fseek (CFILE,0,SEEK_END); // go to end of file
    clen = ftell (CFILE); // get cipher text file length
    rewind (CFILE); // go back to beginning of file
    unsigned char cin[clen]; // get contents of cipher text file
    fread (cin,clen,1,CFILE); // read file contents
    fclose (CFILE); // close file

    // read plaintext file into memory
    FILE *PTFILE; // pointer for plain text file
    PTFILE = fopen (PLAINTEXT,"r"); // open plain text file
    fseek (PTFILE,0,SEEK_END); // go to end of file
    plen = ftell (PTFILE); // get length of contents in total chars
    rewind (PTFILE); // go back to beginning of file
    char pin[plen]; // get contents of plain text file
    fread (pin,plen,1,PTFILE); // read file contents
    fclose (PTFILE); // close file

    // read out contents to user
    printf ("\nPlain text: %s\n",pin);
    fprintf (stderr,"Cipher text: %s\n\n",(char *) cin);

    int i;
    unsigned char key[MAX_KLEN]; // max length for the partial key
    unsigned char tkey[MAX_KLEN]; // max length for the test key

    // ensure the length of the key remains at MAX_KLEN
    if (kdlen > MAX_KLEN) { kdlen = MAX_KLEN; }

    // Copy bytes to the front of the array
    for (i = 0; i < kdlen; i++) {
        key[i] = kd[i];
        tkey[i] = kd[i];
    }

    // if key data less than MAX_KLEN then pad the remaining bytes with zeros
    for (i = kdlen; i < MAX_KLEN; i++) {
        key[i] = 0;
        tkey[i] = 0;
    }

    // unpack remainder bytes
    unsigned long klb = 0;
    for (i = 24; i < MAX_KLEN-1; i++) {
        klb |= ((unsigned long)(key[i] & 0xFFFF) << (((MAX_KLEN-i)*8)-8));
    }
    
    // debugging - prints out KLB (starting point)
    //printf("KLB: %ld\n",klb); 

    // how many bits do we need to complete the key?
    int tkeylen = MAX_KLEN; // make test key length MAX_KLEN
    unsigned long maxSpace = 0;
    maxSpace = ((unsigned long) 1 << ((tkeylen - kdlen) * 8)) - 1;
    
    int j; // this process + loop iterator for nodes
    int cpid; // child process ID
    int pid; // process ID
    unsigned long counter; // loop iterator for decryption
     
    if (make_trivial_ring() < 0) {
        perror("Could not make trivial ring");
        exit(EXIT_FAILURE);
    }; 
    
    // time taken to process - start
    clock_t start = clock();

    // add new node
    for (j = 1; j < nodes; j++) {
        if (add_new_node(&cpid) < 0) {
            perror("Could not add new node to ring");
            exit(EXIT_FAILURE);
        }
        pid = getpid();
        if(cpid) break;
    }

    // write and read searches to ring
    char buff[50];
    if (j == 1) {
        write(STDOUT_FILENO, buff, 19);
        fprintf(stderr, "writing from - %d\n", getpid()); 
    }
    if (j == nodes) {
        read(STDIN_FILENO, buff, 19);
        fprintf(stderr, "result from %d - %s\n", getpid(), buff);
    }
    if ((j > 1) && (j < nodes)) {
        read(STDIN_FILENO, buff, 19);
        write(STDOUT_FILENO, buff, 19);
    }

     // debugging to show parent and child process ID and which node we are -
     // at from total nodes specified by user
    fprintf(stderr, "Node: %d of %d, Parent: %d, Child: %d\n", j,nodes,pid,cpid);
    
    // debugging to ensure keys are partitioning amongst nodes
    // shows for each node, the start and end range of the search
    //fprintf(stderr, 
    //"--------------\nj - %d\nstart - %ld\nend - %ld\n-------------\n", 
    //j, (j-1) * (maxSpace/nodes), j * (maxSpace/nodes)); 
    
    for (counter = (j-1) * (maxSpace/nodes); counter < j * (maxSpace/nodes); 
    counter++)
    {

        //debugging - prints out Counter
        //fprintf(stderr,"Counter: %ld\n",counter); 

        unsigned long tlb = klb | counter;
        //Unpack these bits into the end of the trial key array
        tkey[25] = (unsigned char) (tlb >> 48);
        tkey[26] = (unsigned char) (tlb >> 40);
        tkey[27] = (unsigned char) (tlb >> 32);
        tkey[28] = (unsigned char) (tlb >> 24);
        tkey[29] = (unsigned char) (tlb >> 16);
        tkey[30] = (unsigned char) (tlb >> 8);
        tkey[31] = (unsigned char) (tlb);
        
        // debugging - prints out TLBs
        //fprintf(stderr,"TLB: %ld\n",tlb);

        //Set up the encryption device
        EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new ();
        EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new ();

        // Initialise the encryption device
        if (aes_init (tkey, en, de))
        {
            printf ("Couldn't initialize AES cipher\n");
            return -1;
        }

        // Test permutation of the key to see if we get the desired - plain text
        char *plaintext;
        plaintext = (char *) aes_decrypt (de,(unsigned char *) cin,&clen);

        // Cleanup Cipher Allocated memory
        EVP_CIPHER_CTX_cleanup (en);
        EVP_CIPHER_CTX_cleanup (de);
        EVP_CIPHER_CTX_free (en);
        EVP_CIPHER_CTX_free (de);            

        // if we get a match, readout and end program
        if (strncmp (plaintext, pin, plen) == 0) {       
            fprintf(stderr,"\n\nOK: enc/dec ok for: \"%s\"\n", plaintext);
            fprintf(stderr,"Iterations: %ld, Key No.:",counter);
            int y;
            for (y = 0; y < MAX_KLEN; y++)
            {
                fprintf(stderr,"%c", tkey[y]);
            }
            fprintf (stderr,"\n");         
        }
        free (plaintext);
    }

    // time taken to process - end
    clock_t end = clock();
    // calc time taken from start to end
    float seconds = (float)(end - start) / CLOCKS_PER_SEC;
    // print time taken to user
    if(j==nodes){ fprintf(stderr,"\nTook %f seconds to run.\n\n",seconds); }
}
/*****************************************************************************/


/******************************************************************************
 * Function: make_trivial_ring
 * 
 * creates trivial ring
******************************************************************************/
int make_trivial_ring() {
    int fd[2];
    if (pipe(fd) == -1)
        return (-1);
    if ((dup2(fd[0], STDIN_FILENO) == -1) || (dup2(fd[1], STDOUT_FILENO) == -1))
        return (-2);
    if ((close(fd[0]) == -1) || (close(fd[1]) == -1))
        return (-3);
    return (0);
}
/*****************************************************************************/


/******************************************************************************
 * Function: add_new_node
 * 
 * Add new node
******************************************************************************/
int add_new_node(int *pid) {
    int fd[2];
    if (pipe(fd) == -1) return (-1);
    if ((*pid = fork()) == -1) return (-2);
    if (*pid > 0 && dup2(fd[1], STDOUT_FILENO) < 0) return (-3);
    if (*pid == 0 && dup2(fd[0], STDIN_FILENO) < 0) return (-4);
    if ((close(fd[0]) == -1) || (close(fd[1]) == -1)) return (-5);
    return (0);
}
/*****************************************************************************/


/******************************************************************************
 * Function: aes_init
 * 
 * Initializes encryption/decryption function
******************************************************************************/
int aes_init (unsigned char *kd, EVP_CIPHER_CTX * e_ctx,
	  EVP_CIPHER_CTX * d_ctx)
{
    //Create and initialize the encryption device.
    EVP_CIPHER_CTX_init (e_ctx); 
    EVP_EncryptInit_ex (e_ctx, EVP_aes_256_cbc (), NULL, kd, kd);
    EVP_CIPHER_CTX_init (d_ctx);
    EVP_DecryptInit_ex (d_ctx, EVP_aes_256_cbc (), NULL, kd, kd);

    return 0;
}
/*****************************************************************************/


/*******************************************************************************
 * Function: aes_decrypt
 * 
 * Decrypt *len bytes of ciphertext
 * All data going in & out is considered binary (unsigned char[])
******************************************************************************/
unsigned char *
aes_decrypt (EVP_CIPHER_CTX * e, unsigned char *ciphertext, int *len)
{
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc (p_len);

  EVP_DecryptInit_ex (e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate (e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex (e, plaintext + p_len, &f_len);

  return plaintext;
}
/*****************************************************************************/

/******************************************************************************
 * EOF
******************************************************************************/