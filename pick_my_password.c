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
int buffer_in = 0; // Index para inserir no buffer
int buffer_out = 0; // Index para remover do buffer

char *shadow_hash;  // Essa variável precisa ser inicializada corretamente
struct crypt_data encrypted_data;

// List to store found passwords
char *passwd_found[PASSWD_FOUND_LIST];
int passwd_found_index = 0;

// Função para carregar a lista de senhas ou hashes
int loadpasswd(const char* filename) {
    char passwd[MAX_PASSWORD_LENGTH];
    char hash[MAX_PASSWORD_LENGTH];

    FILE* file = fopen(filename, "r");

    if (file == NULL) {
        perror("fopen():");
        return -1;
    }

    if (strcmp(filename, "hashes.txt") == 0) {
        hash_list = malloc(MAX_HASHS * sizeof(char *));
        if (hash_list == NULL) {
            perror("malloc():");
            fclose(file);
            return -1;
        }
        int i = 0;
        while (i < MAX_HASHS && fgets(hash, MAX_PASSWORD_LENGTH, file) != NULL) {
            hash[strcspn(hash, "\n")] = 0;
            hash_list[i] = strdup(hash);
            if (hash_list[i] == NULL) {
                perror("strdup():");
                fclose(file);
                return -1;
            }
            i++;
        }

        fclose(file);
        return i;

    } else {
        password_list = malloc(MAX_PASSWORDS * sizeof(char *));
        if (password_list == NULL) {
            perror("malloc():");
            fclose(file);
            return -1;
        }

        int i = 0;
        while (i < MAX_PASSWORDS && fgets(passwd, MAX_PASSWORD_LENGTH, file) != NULL) {
            passwd[strcspn(passwd, "\n")] = 0; // Remove newline
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

// Produtor coloca senhas no buffer
void *producer(void *arg) {
    int npasswd = *(int *)arg;

    for (int i = 0; i < npasswd; i++) {
        sem_wait(&empty); // Espera espaço no buffer
        pthread_mutex_lock(&mutex);

        // Coloca a senha no buffer
        buffer[buffer_in] = password_list[i];
        buffer_in = (buffer_in + 1) % BUFFER_SIZE;
        count++;
        
        pthread_mutex_unlock(&mutex);
        sem_post(&full);  // Sinaliza que há dados no buffer
    }
    

    return NULL;
}

// Consumidor verifica senhas
void *consumer(void *arg) {
    int nhashes = *(int *)arg;

    while (1) {
        sem_wait(&full); // Espera dados no buffer
        pthread_mutex_lock(&mutex);

        if (passwd_found || buffer_out == BUFFER_SIZE) { // Se a senha foi encontrada, sai
            pthread_mutex_unlock(&mutex);
            sem_post(&full);
        }

        // Pega a senha do buffer
        char *password = buffer[buffer_out];
        buffer_out = (buffer_out + 1) % BUFFER_SIZE;
        count--;

        pthread_mutex_unlock(&mutex);
        if(buffer_out == BUFFER_SIZE){
        sem_post(&empty); // Sinaliza que há espaço no buffer
        }

        // Configura o `crypt_data` para 0
        encrypted_data.initialized = 0;

        for (int i = 0; i < nhashes; i++) {
            shadow_hash = hash_list[i];
            // Extrai o salt do `shadow_hash`
            strncpy(salt, shadow_hash, 11);  // Verificar se shadow_hash está inicializado corretamente
            salt[11] = '\0'; // Garante terminação correta

            // Utiliza `crypt_r` para gerar o hash
            char *new_hash = crypt_r(password, salt, &encrypted_data);

            // Compara o hash gerado com o `shadow_hash`
            if (strcmp(shadow_hash, new_hash) == 0) {
                printf("Senha encontrada: %s\n", password);
                password_found = 1;
            } /* else{
                printf("password used: %s\n", password);
                printf("password not found: %s\n", new_hash);
                printf("hash to compare: %s\n", shadow_hash);
            } */
        }
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Uso: %s <hash> <arquivo dicionário>\n", argv[0]);
        return 1;
    }

    char *filename = argv[2];
    printf("Usando dicionário: %s\n", filename);

    num_consumers = atoi(argv[1]);

    // Carrega senhas
    int npasswd = loadpasswd(filename);
    if (npasswd == -1) {
        return 1;
    }

    // Carrega hashes
    int nhashes = loadpasswd("hashes.txt");
    if (nhashes == -1) {
        return 1;
    }

    // Inicializa semáforos
    sem_init(&full, 0, 0); // Nenhum slot cheio
    sem_init(&empty, 0, BUFFER_SIZE); // Todos os slots vazios

    // Cria thread produtora
    pthread_t prod_thread;
    pthread_create(&prod_thread, NULL, producer, &npasswd);

    // Cria threads consumidoras
    pthread_t cons_threads[num_consumers];
    for (int i = 0; i < num_consumers; i++) {
        pthread_create(&cons_threads[i], NULL, consumer, &nhashes);
    }

    // Espera a produtora terminar
    pthread_join(prod_thread, NULL);

    // Espera as consumidoras terminarem
    for (int i = 0; i < num_consumers; i++) {
        pthread_join(cons_threads[i], NULL);
    }

    if (!password_found) {
        printf("Senha não encontrada!\n");
    }

    // Libera memória alocada
    for (int i = 0; i < npasswd; i++) {
        free(password_list[i]);
    }
    free(password_list);  // Liberar a memória do shadow_hash

    return 0;
}
