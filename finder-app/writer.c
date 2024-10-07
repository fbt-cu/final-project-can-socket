/* writer.c */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	int fd = 0;
	size_t count = 0;
	ssize_t nr = 0;

	/* Open syslog */
	openlog("writer-app", LOG_NDELAY, 0);

	/* Check for the correct number of arguments */
	if(argc != 3)
	{
		syslog(LOG_ERR, "Incorrect number of arguments, expected 2, received %d\n", argc-1);
		return 1;
	}

	/* Open a file (existing or not) */
	fd = open(argv[1], O_WRONLY | O_CREAT, 0664);
	if(fd == -1)
	{
		/* Error opening file, log and quit */
		syslog(LOG_ERR, "File could not be opened errno: %d\n", errno);
		return -1;
	}
	
	/* Write the contents of the file */
	count = strlen(argv[2]);
	nr = write(fd, argv[2], count);
	if(nr == -1)
	{
		/* Error writing file */
		syslog(LOG_ERR, "Error writing file errno: %d\n", errno);
	}
	/* Write was successful, write into syslog */
	syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);

	/* Close file */
	if(close(fd) == -1)
	{
		/* An error has ocurred while closing the file */
		syslog(LOG_ERR, "An error has ocurred while closing the file errno: %d\n", errno);
		return -1;
	}
	
	/* Close syslog */
	closelog();

	return 0;
}

