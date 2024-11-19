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

typedef struct
{
    int can_s;
    int port;
} ListenerThreadArgs;

typedef struct thread_Node
{
    pthread_t thread_id;
    int client_fd;
    int alive;
    SLIST_ENTRY(thread_Node) entry;
}thread_Node;

// Define the head of the list
SLIST_HEAD(ThreadList, thread_Node) head = SLIST_HEAD_INITIALIZER(head);

// Global mutex for synchronizing access to print
///TODO: this mutex might not be really needed, for now is for debugging purposes
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
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
   new_thread_node->alive = 1;
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
        pthread_kill(current_thread_node->thread_id, SIGINT);
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

void *thread_can_send_to_sockets(void *args)
{
    ListenerThreadArgs *threadArgs = (ListenerThreadArgs *)args;
    struct can_frame frame;
    int nbytes;
    struct sockaddr_can addr;
    struct ifreq ifr;
    socklen_t len = sizeof(addr);
    char send_str[58];

    // Log the creation of this thread
    syslog(LOG_INFO, "Created can%d send to sockets thread.", threadArgs->port);

    while(!exit_main_loop)
    {
        // Read CAN frame (block if none available)
        nbytes = recvfrom(threadArgs->can_s, &frame, sizeof(frame), 0, (struct sockaddr*)&addr, &len);
        if(nbytes > 0)
        {
            // we received data
            ifr.ifr_ifindex = addr.can_ifindex;
            ioctl(threadArgs->can_s, SIOCGIFNAME, &ifr);

            sprintf(send_str, "%s rx %03X %hhd %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX %02hhX\n", ifr.ifr_name, frame.can_id, frame.can_dlc, 
            frame.data[0], frame.data[1], frame.data[2], frame.data[3], frame.data[4], frame.data[5], frame.data[6], frame.data[7]);
        
            syslog(LOG_INFO, "%s", send_str);

            thread_Node* current_thread_node = SLIST_FIRST(&head);
            thread_Node* next_thread_node;
            pthread_mutex_lock(&thread_list_mutex);
            while((current_thread_node != NULL))
            {
                next_thread_node = SLIST_NEXT(current_thread_node,entry);
                if(current_thread_node->alive)
                {
                    if (send(current_thread_node->client_fd, send_str, 38, 0) == -1)
                    {
                        syslog(LOG_ERR, "Send to client failed: %s", strerror(errno));
                        break;
                    }
                }
                current_thread_node = next_thread_node;
            }
            pthread_mutex_unlock(&thread_list_mutex);

        }
    }
}

void *thread_function(void *args)
{
    ThreadArgs *threadArgs = (ThreadArgs *)args;
    char client_ip[INET_ADDRSTRLEN];
    struct can_frame frame;
    int nbytes;
    pthread_t self;

    self = pthread_self();

    memset(&frame, 0, sizeof(struct can_frame));
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

    // start receiving command from connection
    while(!exit_main_loop)
    {
        char rec_cmd[35];
        char close[6];
        char rest[29];
        int port;
        int socket;
        // can1 123 8 01 02 03 04 05 06 07 08
        nbytes = recv(threadArgs->client_fd, rec_cmd, 35, 0);
        if(nbytes <= 0)
        {
            // interrupted
            break;
        }

        sscanf(rec_cmd, "%s %s", close, rest);
        if(strcmp(close, "close") == 0)
        {
            // close connection
            break;
        }

        sscanf(rec_cmd, "can%d %X %hhd %hhX %hhX %hhX %hhX %hhX %hhX %hhX %hhX\n", &port, &frame.can_id, &frame.can_dlc, 
        &frame.data[0], &frame.data[1], &frame.data[2], &frame.data[3], &frame.data[4], &frame.data[5], &frame.data[6], &frame.data[7]);
        
        if(port == 0)
        {
            socket = threadArgs->can0_s;
        }
        else if(port == 1)
        {
            socket = threadArgs->can1_s;
        }
        else
        {
            syslog(LOG_ERR, "Selected CAN port does not exist");

        }

        nbytes = write(socket, &frame, sizeof(frame)); 
        if(nbytes != sizeof(frame)) {
            syslog(LOG_ERR, "Error sending frame to can port can%d", port);
        }
    }

    if (close(threadArgs->client_fd) == 0)
    {
        syslog(LOG_INFO, "Closed connection from %s", client_ip);
    }
    else
    {
        syslog(LOG_ERR, "Closing of connection from %s failed", client_ip);
    }

    if(exit_main_loop)
    {
        // we were signaled to exit, no need to set the alive value to 0, just return from here
        return 0;
    }

    thread_Node* current_thread_node = SLIST_FIRST(&head);
    thread_Node* next_thread_node;
    pthread_mutex_lock(&thread_list_mutex);
    while((current_thread_node != NULL))
    {
        next_thread_node = SLIST_NEXT(current_thread_node,entry);
        if(pthread_equal(current_thread_node->thread_id,self)!=0)
        {
            current_thread_node->alive = 0;
            break;
        }
        current_thread_node = next_thread_node;
    }
    pthread_mutex_unlock(&thread_list_mutex);

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

    ///TODO: Maybe we need loopback, maybe not, for now we will disable it
    // Disable loopback 
    int loopback = 0;
    int setsockopt_ret;
    setsockopt_ret = setsockopt(can0_s, SOL_CAN_RAW, CAN_RAW_LOOPBACK, &loopback, sizeof(loopback));
    syslog(LOG_INFO, "Set socket option loopback to %d in port can0. Result: %d", loopback, setsockopt_ret);
    setsockopt_ret = setsockopt(can1_s, SOL_CAN_RAW, CAN_RAW_LOOPBACK, &loopback, sizeof(loopback));
    syslog(LOG_INFO, "Set socket option loopback to %d in port can1. Result: %d", loopback, setsockopt_ret);
    setsockopt_ret = setsockopt(can0_s, SOL_CAN_RAW, CAN_RAW_RECV_OWN_MSGS, &loopback, sizeof(loopback));
    syslog(LOG_INFO, "Set socket option receive own messages to %d in port can0. Result: %d", loopback, setsockopt_ret);
    setsockopt_ret = setsockopt(can1_s, SOL_CAN_RAW, CAN_RAW_RECV_OWN_MSGS, &loopback, sizeof(loopback));
    syslog(LOG_INFO, "Set socket option receive own messages to %d in port can1. Result: %d", loopback, setsockopt_ret);

    // Create and launch CAN0 listener thread (thread_can_send_to_sockets)
    pthread_t threadListener0Id;
    ListenerThreadArgs *argsListener0 = malloc(sizeof(ListenerThreadArgs));
    if (argsListener0 == NULL)
    {
        syslog(LOG_ERR, "Failed to allocate memory for CAN0 listener thread arguments");
    }
    // Use can0 socket
    argsListener0->can_s = can0_s;
    argsListener0->port = 0;
    syslog(LOG_INFO, "Creating can0 listener thread");
    if (pthread_create(&threadListener0Id, NULL, thread_can_send_to_sockets, (void *)argsListener0) != 0)
    {
        syslog(LOG_ERR, "Error creating can0 listener thread");
        free(argsListener0);
    }

    // Create and launch CAN1 listener thread (thread_can_send_to_sockets)
    pthread_t threadListener1Id;
    ListenerThreadArgs *argsListener1 = malloc(sizeof(ListenerThreadArgs));
    if (argsListener1 == NULL)
    {
        syslog(LOG_ERR, "Failed to allocate memory for CAN1 listener thread arguments");
    }
    // Use can1 socket
    argsListener1->can_s = can1_s;
    argsListener1->port = 1;
    syslog(LOG_INFO, "Creating can1 listener thread");
    if (pthread_create(&threadListener1Id, NULL, thread_can_send_to_sockets, (void *)argsListener1) != 0)
    {
        syslog(LOG_ERR, "Error creating can1 listener thread");
        free(argsListener1);
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
    pthread_kill(threadListener0Id, SIGINT);
    pthread_kill(threadListener1Id, SIGINT);
    pthread_join(threadListener0Id, NULL);
    pthread_join(threadListener1Id, NULL);

    close(can0_s);
    close(can1_s);

    freeaddrinfo(server_info);
    closelog();
}