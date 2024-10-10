#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
//#define DEBUG_LOG(msg,...)
#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    
	//DEBUG_LOG("Inside thread, start wait to obtain");
	// Sleep for wait_to_obtain_ms
        usleep(((struct thread_data*)thread_param)->wait_to_obtain_ms * 1);
	//DEBUG_LOG("Finished wait to obtain, obtaining mutex");
	// Obtain mutex
	pthread_mutex_lock(((struct thread_data*)thread_param)->mutex);
	//DEBUG_LOG("Obtained mutex, start wait to release");
	// Sleep for wait_to_release_ms
	usleep(((struct thread_data*)thread_param)->wait_to_release_ms * 1);
	//DEBUG_LOG("Finished wait to release, releasing mutex");
	// Release mutex
	pthread_mutex_unlock(((struct thread_data*)thread_param)->mutex);
	//DEBUG_LOG("Released mutex, ending thread");
	return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
    
	// Allocate thread_data and initialize
	struct thread_data *data;
	data = malloc(sizeof(struct thread_data));
	data->mutex = mutex;
	data->wait_to_obtain_ms = wait_to_obtain_ms * 1000;
	data->wait_to_release_ms = wait_to_release_ms * 1000;
	data->thread_complete_success = true;
	//DEBUG_LOG("Configured struct, creating thread next.");
	// Create thread
	if(0 == pthread_create(thread, NULL, threadfunc, data))
		return true;
	else
		return true;

}

