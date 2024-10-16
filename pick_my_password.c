#include <stdio.h>
#include <string.h>
#include <crypt.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>

#define MAX_PASSWORDS 15000000
#define MAX_PASSWORD_LENGTH 128
#define BUFFER_SIZE 1000
#define PASSWD_FOUND_LIST 500


int num_consumers;
int password_found = 0;
int count = 0;

char salt[12];

// Semaphores and mutex initialization
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
sem_t full;
sem_t empty;


char **password_list;
char *buffer[BUFFER_SIZE];
int buffer_index = 0;

char *shadow_hash;
char salt[12];
struct crypt_data encrypted_data;

//list to store found passwords
char *passwd_found[PASSWD_FOUND_LIST];
int passwd_found_index = 0;

int loadpasswd(const char* filename){
    char passwd[MAX_PASSWORD_LENGTH];
    FILE* file = fopen(filename, "r");

    if(file == NULL){
        perror("fopen():");
        return -1;
    }
    password_list = malloc(MAX_PASSWORDS * sizeof(char *));

    int i = 0;

    while(i < MAX_PASSWORDS && fgets(passwd, MAX_PASSWORD_LENGTH, file) != NULL){
        passwd[strcspn(passwd,"\n")] = 0; // Remove newline
        password_list[i] = strdup(passwd);
        i++;
    }

    fclose(file);
    return i;
}

void *producer(void *arg){
    int npasswd = *(int *) arg;

    for(int i = 0; i < npasswd; i++){
        pthread_mutex_lock(&mutex);
        sem_wait(&empty);
        while(count == BUFFER_SIZE){
            sem_post(&empty); // Notify consumers
            sem_wait(&full); // Producer wait until buffer be empty
        }

        // Put passwd in the buffer
        buffer[buffer_index] = password_list[i];
        buffer_index = (buffer_index + 1) % BUFFER_SIZE;
        count++;

        // Notify consumers
        sem_post(&empty);

        pthread_mutex_unlock(&mutex);
    }

    return NULL;
}

void *consumer(void *arg){
    while(!password_found){
        pthread_mutex_lock(&mutex);
        while(count == 0 && !password_found){
            sem_wait(&empty);
            sem_post(&full);
        }

        if(password_found){
            pthread_mutex_unlock(&mutex);
        }
        
        //geting password from buffer
        char password = *(char *)buffer[buffer_index - count + BUFFER_SIZE] % BUFFER_SIZE;
        count--;

        //The password hash from the shadow file (user-provided example)
        pthread_mutex_unlock(&mutex);

        //Notify producer
        sem_post(&full);

        //Setting crypt_data to 0;
        encrypted_data.initialized = 0;

        // Extracting the salt from the shadow_hash, it includes "$1$"
        strncpy(salt, shadow_hash, 11);
        salt[11] = '\0'; // Ensure null termintation
        
        //Utilizar crypt_r() aqui
        char *new_hash = crypt_r(&password, salt, &encrypted_data);

        if(strcmp(shadow_hash, new_hash) == 0){
                printf("Password found: %s\n", &password);
                password_found = 1;

                // Putting found password in a buffer  
                passwd_found[passwd_found_index] = &password;
                passwd_found_index++;
                break;
            }
        return NULL;
    }
}

int main(int argc, char* argv[]){

    //Checking number of args
    if(argc < 3){
        printf("Usage: %s <hash> <dict file>\n", argv[0]);
        return 1;
    }

    //Getting dict name
    char filename = *(char *) argv[2];

    //Getting number of consumers
    int num_consumers = atoi(argv[1]);

    //Setting number of threads as shadow_hash to add in salt string
    shadow_hash = argv[1];
    
    //Checking if loadpasswd was succesfull
    int npasswd = loadpasswd(&filename);
    if(npasswd == -1){
        return 1;
    }

    //producer thread
    pthread_t prod_thread;
    pthread_create(&prod_thread, NULL, producer, &npasswd);

    //multiples consumer threads
    pthread_t cons_threads[num_consumers];
    for(int i=0; i < num_consumers; i++){
        pthread_create(&cons_threads[i], NULL, consumer, NULL);
    }

    //Waiting until producer thread finish fulfill the buffer
    pthread_join(prod_thread, NULL);

    //Waiting until consumer threads finish empty the buffer
    for(int i=0; i<num_consumers ; i++){
        pthread_join(cons_threads[i],NULL);
    }

    
    if(!password_found){
        printf("Password not found!\n");
    }

    //freeing memory of passwordlist as producer take a batch of password on rockyou.txt
    for(int i=0; i<npasswd; i++){
        free(password_list[i]);
    }
    free(password_list);

    return 0;
}   