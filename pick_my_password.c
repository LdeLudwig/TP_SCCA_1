#include <stdio.h>
#include <string.h>
#include <crypt.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>

#define MAX_PASSWORDS 15000000
#define MAX_PASSWORD_LENGTH 128
#define BUFFER_SIZE 1000

int num_consumers; 
int password_found = 0;
int count = 0;

char salt[12];

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
sem_t full;
sem_t empty;

char **password_list;
char *buffer[BUFFER_SIZE];
int buffer_index;



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

    sem_wait(&full);

    for(int i = 0; i < npasswd; i++){
        pthread_mutex_lock(&mutex);
        while(count == BUFFER_SIZE){
            sem_wait(&full); // Producer wait until buffer be empty
        }

        // Coloca senha no buffer
        buffer[buffer_index] = password_list[i];
        buffer_index = (buffer_index + 1) % BUFFER_SIZE;
        count++;

        sem_signal(&empty); // Notifica consumidores
        pthread_mutex_unlock(&mutex);
    }
}

void *consumer(void *arg){

}

int main(int argc, char* argv[]){
    //producer thread
    pthread_t prod_thread;

    //Get dictionary name
    char filename = *(char *) argv[2];
    int npasswd = loadpasswd(filename);
    
    if(npasswd == -1){
        return 1;
    }

    pthread_create(&prod_thread, NULL, producer, &npasswd);

    int con_num = atoi(argv[1]);


    if(argc < 3){
        printf("Usage: %s <hash> <dict file>\n", argv[0]);
        return 1;
    }

    //The password hash from the shadow file (user-provided example)
    char *shadow_hash;
    char salt[12];
    struct crypt_data encrypted_data;


    shadow_hash = argv[0];

    // Extracting the salt from the shadow_hash, it includes "$1$"
    strncpy(salt, shadow_hash, 11);
    salt[11] = '\0'; // Ensure null termintation

    for (int i=0; i<npasswd; i++){
        //Utilizar crypt_r() aqui
        char *new_hash = crypt(password_list[i], salt);
        if(strcmp(shadow_hash, new_hash) == 0){
            printf("Password found: %s\n", password_list[i]);
            return 0;
        }
    }

    printf("Password not found!");

    return 0;
}   