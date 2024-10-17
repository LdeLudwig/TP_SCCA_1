#include <stdio.h>
#include <string.h>
#include <crypt.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>

#define MAX_PASSWORDS 15000000
#define MAX_PASSWORD_LENGTH 128
#define BUFFER_SIZE 10000
#define PASSWD_FOUND_LIST 500
#define MAX_HASHS 600

int num_consumers;
int password_found = 0;
int count = 0;

char salt[12];

// Semaphores and mutex initialization
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
sem_t full;
sem_t empty;

char **password_list;
char **hash_list;

char *buffer[BUFFER_SIZE];
int buffer_index = 0;

char *shadow_hash;
char salt[12];
struct crypt_data encrypted_data;

// List to store found passwords
char *passwd_found[PASSWD_FOUND_LIST];
int passwd_found_index = 0;

int loadpasswd(const char* filename){
    char passwd[MAX_PASSWORD_LENGTH];
    char hash[MAX_PASSWORD_LENGTH];

    FILE* file = fopen(filename, "r");

    if(file == NULL){
        perror("fopen():");
        return -1;
    }

    //routine for hashes.txt
    if(strcmp(filename,"hashes.txt") == 0){
        hash_list = malloc(MAX_HASHS * sizeof(char *));
        if(hash_list == NULL){
            perror("malloc():");
            fclose(file);
            return -1;
        }
        int i = 0;
        while(i < MAX_HASHS && fgets(hash, MAX_PASSWORD_LENGTH, file) != NULL){
            hash[strcspn(hash,"\n")] = 0;
            hash_list[i] = strdup(hash);
            if(hash_list[i] = NULL){
                perror("strdup():");
                fclose(file);
                return -1;
            }
            i++;
        }

        fclose(file);
        return i;

    //routine for rockyou
    }else{
        password_list = malloc(MAX_PASSWORDS * sizeof(char *));
        if(password_list == NULL){
            perror("malloc():");
            fclose(file);
            return -1;
        }

        int i = 0;
        while(i < MAX_PASSWORDS && fgets(passwd, MAX_PASSWORD_LENGTH, file) != NULL){
            passwd[strcspn(passwd,"\n")] = 0; // Remove newline
            password_list[i] = strdup(passwd);
            if (password_list[i] == NULL) {
                perror("strdup():");
                fclose(file);
                return -1;
            }
            i++;
        }
        
            fclose(file);
            return i;
    }     
}

void *producer(void *arg){
    int npasswd = *(int *) arg;

    for(int i = 0; i < npasswd; i++){
        sem_wait(&empty); // Wait until there's space in the buffer
        pthread_mutex_lock(&mutex);

        // Put passwd in the buffer
        buffer[buffer_index] = password_list[i];
        buffer_index = (buffer_index + 1) % BUFFER_SIZE;
        count++;

        // Notify consumers
        pthread_mutex_unlock(&mutex);
        sem_post(&full);  // Signal that buffer has data
    }

    return NULL;
}

void *consumer(void *arg){
    int nhashes = *(int *) arg;

    while(!password_found){
        sem_wait(&full); // Wait until there's data in the buffer
        pthread_mutex_lock(&mutex);

        if(password_found){ // If password found, unlock and exit
            pthread_mutex_unlock(&mutex);
            sem_post(&full);
            break;
        }

        // Getting password from buffer
        char *password = buffer[(buffer_index - count + BUFFER_SIZE) % BUFFER_SIZE];
        count--;

        // Notify producer
        pthread_mutex_unlock(&mutex);
        sem_post(&empty); // Signal that buffer has space

        // Setting crypt_data to 0
        encrypted_data.initialized = 0;

        for(int i=0; i < nhashes; i++){
            // Extracting the salt from the shadow_hash, it includes "$1$"
            strncpy(salt, shadow_hash, 11);
            salt[11] = '\0'; // Ensure null termination
            
            // Utilize crypt_r() to generate the hash with the format $1$salt$hash
            char *new_hash = crypt_r(password, salt, &encrypted_data);

            // Check if the hash matches the shadow hash
            if(strcmp(shadow_hash, new_hash) == 0){
                printf("Password found: %s\n", password);
                password_found = 1;

                // Putting found password in a buffer
                pthread_mutex_lock(&mutex);
                passwd_found[passwd_found_index] = strdup(password);
                passwd_found_index++;
                pthread_mutex_unlock(&mutex);

                break;
            }
        }
    }
    return NULL;
}

int main(int argc, char* argv[]){

    // Checking number of args
    if(argc < 3){
        printf("Usage: %s <hash> <dict file>\n", argv[0]);
        return 1;
    }

    // Getting dict name
    char *filename = argv[2];
    printf("Using dictionary: %s\n", filename);

    // Getting number of consumers
    num_consumers = atoi(argv[1]);

    // Calling loadpasswd for rockyou
    int npasswd = loadpasswd(filename);

    // Checking if loadpasswd was successful
    if(npasswd == -1){
        return 1;
    }

    // Calling loadpasswd for hashes
    int nhashes = loadpasswd("hashes.txt");

    // Checking if loadpasswd was successful
    if(nhashes == -1){
        return 1;
    }

    // Initialize semaphores
    sem_init(&full, 0, 0); // Initially no full slots
    sem_init(&empty, 0, BUFFER_SIZE); // All slots are empty

    // Producer thread
    pthread_t prod_thread;
    pthread_create(&prod_thread, NULL, producer, &npasswd);

    // Multiple consumer threads
    pthread_t cons_threads[num_consumers];
    for(int i = 0; i < num_consumers; i++){
        pthread_create(&cons_threads[i], NULL, consumer, &nhashes);
    }

    // Waiting until producer thread finishes fulfilling the buffer
    pthread_join(prod_thread, NULL);

    // Waiting until consumer threads finish emptying the buffer
    for(int i = 0; i < num_consumers; i++){
        pthread_join(cons_threads[i], NULL);
    }

    if(!password_found){
        printf("Password not found!\n");
    }

    // Freeing memory
    for(int i = 0; i < npasswd; i++){
        free(password_list[i]);
    }
    free(password_list);

    return 0;
}
