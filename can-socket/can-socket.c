/******************************************************
# can-socket application
# Author: Fernando Becerra Tanaka <fernando.becerratanaka@colorado.edu>
# Based on the work of Induja Narayanan <Induja.Narayanan@colorado.edu>
******************************************************/
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/queue.h>
#include <time.h>
#include <sys/ioctl.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include "../aesd-char-driver/aesd_ioctl.h" 

#define CLIENT_BUFFER_LEN 1024

bool exit_main_loop = false;
typedef struct
{
    int client_fd;
    int can0_s, can1_s;
    struct sockaddr_storage socket_addr;
} ThreadArgs;

typedef struct thread_Node
{
    pthread_t thread_id;
    int client_fd;
    SLIST_ENTRY(thread_Node) entry;
}thread_Node;

// Define the head of the list
SLIST_HEAD(ThreadList, thread_Node) head = SLIST_HEAD_INITIALIZER(head);

// Global mutex for synchronizing access to the file
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
// Global mutex for synchronizing access to the thread nodes
pthread_mutex_t thread_list_mutex = PTHREAD_MUTEX_INITIALIZER;

void add_thread_node(pthread_t thread_id, int client_fd)
{
   thread_Node* new_thread_node = malloc(sizeof(thread_Node));
   if(!new_thread_node)
   {
    syslog(LOG_ERR,"Failed to allocate memory for thread node");
    return;
   }
   new_thread_node->thread_id = thread_id;
   new_thread_node->client_fd = client_fd;
   pthread_mutex_lock(&thread_list_mutex);
   syslog(LOG_INFO,"Inserting thread node");
   SLIST_INSERT_HEAD(&head,new_thread_node,entry);
   pthread_mutex_unlock(&thread_list_mutex);

}

void wait_for_all_threads_to_join()
{
    thread_Node* current_thread_node = SLIST_FIRST(&head);
    thread_Node* next_thread_node;
    pthread_mutex_lock(&thread_list_mutex);
    while((current_thread_node != NULL))
    {
        next_thread_node = SLIST_NEXT(current_thread_node,entry);
        if(pthread_join(current_thread_node->thread_id,NULL)==0)
        {
            syslog(LOG_INFO,"Removing the thread node");
            SLIST_REMOVE(&head,current_thread_node,thread_Node,entry);
            free(current_thread_node);
        }
        else
        {
            syslog(LOG_INFO,"Thread %ld was not able to join: %s",current_thread_node->thread_id, strerror(errno));
        }
        current_thread_node = next_thread_node;
    }
  
    pthread_mutex_unlock(&thread_list_mutex);
}

bool create_daemon()
{
    pid_t pid;
    pid = fork();
    bool status = false;
    int dev_null_fd;

    if (pid < 0)
    {
        syslog(LOG_ERR, "Fork failed");
        return status;
    }

    if (pid > 0)
    {
        // Parent process hence exit
        exit(EXIT_SUCCESS);
    }

    // create new group and session
    if (setsid() < 0)
    {
        syslog(LOG_ERR, "Create new session  failed");
        return status;
    }

    // Change the working directory to "/"
    if (chdir("/") == -1)
    {
        syslog(LOG_ERR, "Changing working directory failed");
        return status;
    }
    // Since no files were open in parent, no fds are closed here
    //  Redirect STDIN , STDOUT and STDERR to /dev/null
    dev_null_fd = open("/dev/null", O_RDWR);
    if (dev_null_fd == -1)
    {
        perror("Failed to open /dev/null");
        return status;
    }

    // Redirect stdin (fd 0) to /dev/null
    if (dup2(dev_null_fd, STDIN_FILENO) == -1)
    {
        perror("Failed to redirect stdin");
        close(dev_null_fd);
        return status;
    }

    // Redirect stdout (fd 1) to /dev/null
    if (dup2(dev_null_fd, STDOUT_FILENO) == -1)
    {
        perror("Failed to redirect stdout");
        close(dev_null_fd);
        return status;
    }

    // Redirect stderr (fd 2) to /dev/null
    if (dup2(dev_null_fd, STDERR_FILENO) == -1)
    {
        perror("Failed to redirect stderr");
        close(dev_null_fd);
        return status;
    }

    // Close the original /dev/null file descriptor
    close(dev_null_fd);
    return true;
}

void signal_handler(int signal)
{
    if (signal == SIGINT)
    {
        syslog(LOG_INFO, "Caught SIGINT (Ctrl+C), exiting gracefully\n");
    }
    else if (signal == SIGTERM)
    {
        syslog(LOG_INFO, "Caught SIGTERM, exiting gracefully\n");
    }
    // Set the global variable so the main server exits gracefully
    exit_main_loop = true;
}

void initialize_sigaction()
{
    struct sigaction sighandle;
    // Initialize sigaction
    sighandle.sa_handler = signal_handler;
    sigemptyset(&sighandle.sa_mask); // Initialize the signal set to empty
    sighandle.sa_flags = 0;          // No special flags

    // Catch SIGINT
    if (sigaction(SIGINT, &sighandle, NULL) == -1)
    {
        syslog(LOG_ERR, "Error setting up signal handler SIGINT: %s \n", strerror(errno));
    }

    // Catch SIGTERM
    if (sigaction(SIGTERM, &sighandle, NULL) == -1)
    {
        syslog(LOG_ERR, "Error setting up signal handler SIGINT: %s \n", strerror(errno));
    }
}

int receive_and_store_socket_data(int client_fd, int file_fd)
{
    char *client_buffer = NULL;
    size_t total_received = 0;
    size_t current_size = CLIENT_BUFFER_LEN;
    size_t multiplication_factor = 1;
    struct aesd_seekto seek_to; // Struct for AESDCHAR_IOCSEEKTO

    // Dynamically allocate initial buffer
    client_buffer = (char *)calloc(current_size, sizeof(char));
    if (client_buffer == NULL)
    {
        syslog(LOG_ERR, "Client buffer allocation failed, returning with error");
        return -1;
    }

    while (true)
    {
        // Receive data from client
        ssize_t received_no_of_bytes = recv(client_fd, client_buffer + total_received, current_size - total_received - 1, 0);
        if (received_no_of_bytes <= 0)
        {
            break; // Connection closed or error
        }
        total_received += received_no_of_bytes;
        client_buffer[total_received] = '\0'; // Null-terminate the string

        // Check for newline
        if (strchr(client_buffer, '\n') != NULL)
        {
            break; // Newline found, exit the loop
        }

        // If we reach this point, we need to resize the buffer
        multiplication_factor <<= 1;
        size_t new_size = multiplication_factor * CLIENT_BUFFER_LEN;
        char *new_buffer = (char *)realloc(client_buffer, new_size);
        if (new_buffer == NULL)
        {
            syslog(LOG_ERR, "Reallocation of client buffer failed, returning with error");
            free(client_buffer);
            return -1;
        }
        client_buffer = new_buffer;
        current_size = new_size;
    }

    // Now we have the complete data, store it in the file
    syslog(LOG_INFO, "Writing received data to the sockedata file");
    // Lock the mutex before writing to the file
    pthread_mutex_lock(&file_mutex);
    if (write(file_fd, client_buffer, total_received) != -1)
    {
        syslog(LOG_INFO, "Syncing data to the disk");
        fdatasync(file_fd);
    }
    else
    {
        syslog(LOG_ERR, "Writing received data to the socketdata file failed");
        pthread_mutex_unlock(&file_mutex); //Unlock mutex before returning from function
        free(client_buffer);
        return -1;
    }
    // UnLock the mutex after writing to the file
    pthread_mutex_unlock(&file_mutex);
    syslog(LOG_INFO, "Unlocked mutex and returning from write");
    free(client_buffer);
    return 0; // Return success
}

int return_socketdata_to_client(int client_fd, int file_fd)
{
    char *send_buffer;
    size_t bytes_read;
    lseek(file_fd, 0, SEEK_SET);
    send_buffer = (char *)malloc(CLIENT_BUFFER_LEN);
    if (send_buffer == NULL)
    {
        syslog(LOG_INFO, "Client buffer was not allocated hence returning with error");
        return -1;
    }


    // Lock the mutex while reading from the file
    pthread_mutex_lock(&file_mutex);
    // Read and send data
    while ((bytes_read = read(file_fd, send_buffer, sizeof(send_buffer) - 1)) > 0)
    {
       
        send_buffer[bytes_read] = '\0';
        syslog(LOG_ERR, "Send to client is: %s", send_buffer);
        // Send to client
        if (send(client_fd, send_buffer, bytes_read, 0) == -1)
        {
            syslog(LOG_ERR, "Send to client failed: %s", strerror(errno));
            break;
        }
    }
    //Unlock the mutex after reading from file
    pthread_mutex_unlock(&file_mutex); 
    syslog(LOG_INFO, "Unlocked the mutex and returning from send routine");
    free(send_buffer);
    return 0;
}

void *thread_can_send_to_sockets(void *args)
{
    ThreadArgs *threadArgs = (ThreadArgs *)args;
    struct can_frame frame;
    int nbytes;

    // Log the creation of this thread
    syslog(LOG_INFO, "Created can send to sockets thread.");

    // Read CAN frame (block if none available)
    nbytes = read(threadArgs->can0_s, &frame, sizeof(frame));
    if(nbytes > 0)
    {
        // we received data
        /// TODO: Go through linked list and send the can data (formatted) 
    }
}

void *thread_function(void *args)
{
    ThreadArgs *threadArgs = (ThreadArgs *)args;
    char client_ip[INET_ADDRSTRLEN];
    // Convert binary IP address from binary to human readable format

    if (threadArgs->socket_addr.ss_family == AF_INET)
    { // Check if the address is IPv4
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&threadArgs->socket_addr;
        inet_ntop(AF_INET, &(addr_in->sin_addr), client_ip, sizeof(client_ip));
    }
    else if (threadArgs->socket_addr.ss_family == AF_INET6)
    { // Check if the address is IPv6
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&threadArgs->socket_addr;
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), client_ip, sizeof(client_ip));
    }

    // Log the client ip
    syslog(LOG_INFO, "Accepted connection from %s", client_ip);

    // Receive packets from the client and store in SOCKETDATA_FILE
    if (receive_and_store_socket_data(threadArgs->client_fd, threadArgs->can0_s) == 0)
    {
        // Send back the stored data of file back to the client
        syslog(LOG_INFO, "Sending back the received data to client");
        return_socketdata_to_client(threadArgs->client_fd, threadArgs->can0_s);
    }

    if (close(threadArgs->client_fd) == 0)
    {
        syslog(LOG_INFO, "Closed connection from %s", client_ip);
    }
    else
    {
        syslog(LOG_ERR, "Closing of connection from %s failed", client_ip);
    }

    // Exit from the thread
    return 0;
}

int main(int argc, char **argv)
{
    struct addrinfo inputs, *server_info;
    int socket_fd, client_fd;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_size;
    int can0_s, can1_s;
    int status;
    int yes = 1;
    bool daemon_mode = false;
    struct sockaddr_can addr0, addr1;
    struct ifreq ifr0, ifr1;
    int ret;

    // Check if the application to be run in daemon mode
    if ((argc >= 2) && (strcmp(argv[1], "-d") == 0))
    {
        daemon_mode = true;
    }

    // Open a system logger connection for aesdsocket utility
    openlog("can-socket", LOG_CONS | LOG_PID | LOG_PERROR, LOG_USER);

    /*Line  was partly referred from https://beej.us/guide/bgnet/html/#socket */
    memset(&inputs, 0, sizeof(inputs));
    inputs.ai_family = AF_UNSPEC;     // IPv4 or IPv6
    inputs.ai_socktype = SOCK_STREAM; // TCP stream sockets
    inputs.ai_flags = AI_PASSIVE;     // fill in my IP for me

    // Get address info
    if ((status = getaddrinfo(NULL, "9000", &inputs, &server_info)) != 0)
    {
        syslog(LOG_ERR, "Error occurred while getting the address info: %s \n", gai_strerror(status));
        closelog();
        exit(1);
    }

    // Open a stream socket
    socket_fd = socket(server_info->ai_family, server_info->ai_socktype, server_info->ai_protocol);
    if (socket_fd == -1)
    {
        syslog(LOG_ERR, "Error occurred while creating a socket: %s\n", strerror(errno));
        freeaddrinfo(server_info);
        closelog();
        exit(1);
    }

    // Set socket options
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
    {
        syslog(LOG_ERR, "Error occurred while setting a socket option: %s \n", strerror(errno));
        freeaddrinfo(server_info);
        closelog();
        exit(1);
    }

    if (bind(socket_fd, server_info->ai_addr, server_info->ai_addrlen) == -1)
    {
        syslog(LOG_ERR, "Error occurred while binding a socket: %s \n", strerror(errno));
        freeaddrinfo(server_info);
        closelog();
        exit(1);
    }

    // Check if daemon needs to be created
    if (daemon_mode)
    {
        if (!create_daemon())
        {
            syslog(LOG_ERR, "Daemon creation failed, hence exiting");
            freeaddrinfo(server_info);
            closelog();
            exit(1);
        }
    }

    if (listen(socket_fd, 20) == -1)
    {
        syslog(LOG_ERR, "Error occurred during listen operation: %s \n", strerror(errno));
        freeaddrinfo(server_info);
        closelog();
        exit(1);
    }

    initialize_sigaction();
    client_addr_size = sizeof(client_addr);

    // Create CAN sockets
    can0_s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (can0_s < 0) {
        syslog(LOG_ERR, "CAN0 socket PF_CAN failed");
        exit(1);
    }
    can1_s = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (can1_s < 0) {
        syslog(LOG_ERR, "CAN1 socket PF_CAN failed");
        exit(1);
    }

    // Specify CAN devices
    strcpy(ifr0.ifr_name, "can0");
    ret = ioctl(can0_s, SIOCGIFINDEX, &ifr0);
    if (ret < 0) {
        syslog(LOG_ERR, "can0 ioctl failed");
        exit(1);
    }
    strcpy(ifr1.ifr_name, "can1");
    ret = ioctl(can1_s, SIOCGIFINDEX, &ifr1);
    if (ret < 0) {
        syslog(LOG_ERR, "can1 ioctl failed");
        exit(1);
    }

    // Bind sockets to CAN0 and CAN1
    addr0.can_family = PF_CAN;
    addr0.can_ifindex = ifr0.ifr_ifindex;
    ret = bind(can0_s, (struct sockaddr *)&addr0, sizeof(addr0));
    if (ret < 0) {
        syslog(LOG_ERR, "can0 bind failed");
        exit(1);
    }
    addr1.can_family = PF_CAN;
    addr1.can_ifindex = ifr1.ifr_ifindex;
    ret = bind(can1_s, (struct sockaddr *)&addr1, sizeof(addr1));
    if (ret < 0) {
        syslog(LOG_ERR, "can1 bind failed");
        exit(1);
    }

    // Main server loop
    while (!exit_main_loop)
    {
        client_fd = accept(socket_fd, (struct sockaddr *)&client_addr, &client_addr_size);
        if (client_fd == -1)
        {
            syslog(LOG_ERR, "Error occurred during accept operation: %s \n", strerror(errno));
            continue;
        }

        pthread_t threadId;
        ThreadArgs *args = malloc(sizeof(ThreadArgs));
        if (args == NULL)
        {
            syslog(LOG_ERR, "Failed to allocate memory for thread arguments");
            close(client_fd);
            continue;
        }

        args->client_fd = client_fd;
        args->socket_addr = client_addr;

        // Use can0 and can1 sockets
        args->can0_s = can0_s;
        args->can1_s = can1_s;

        syslog(LOG_INFO, "Creating a new thread");
        int err = pthread_create(&threadId, NULL, thread_function, (void *)args);
        if (err != 0)
        {
            syslog(LOG_ERR, "Error creating thread: %s", strerror(err));
            close(client_fd);
            free(args);
            continue;
        }

        add_thread_node(threadId, client_fd);
    }

    // Clean up before exiting
    syslog(LOG_ERR, "Waiting for active threads to join");
    wait_for_all_threads_to_join();

    close(can0_s);
    close(can1_s);

    freeaddrinfo(server_info);
    closelog();
}