#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/wait.h>
#include "smartalloc.h"

#define BUFSIZE 4096
#define GET_ERROR (1 << 14)
#define URL_ERROR (1 << 13)
#define VERSION_ERROR (1 << 12)
#define HTTP_ERROR (0x7 << 12)
#define FORTUNE_URL (1 << 8)
#define STAT_URL (1 << 7)
#define QUIT_URL (1 << 6)
#define ABOUT_URL (1 << 5)
#define IMPL_URL (1 << 4)
#define HTTP_1_1 (1 << 2)
#define HTTP_1_0 (1 << 1)
#define HTTP_0_9 (1 << 0)
#define READ_STATE 2
#define WRITE_STATE 1
#define DONE_STATE 0
#define TRUE 1
#define FALSE 0

static int num_clients = 0;
static int num_requests = 0;
static int num_errors = 0;

typedef struct node {
   int fd;
   uint8_t request[BUFSIZE+1];
   uint8_t response[BUFSIZE+1];
   int reqoffset;
   int respoffset;
   int state;
   struct node *next;
} node_t;

static node_t *head = NULL;

/* Linked List Functions */

int in_list(node_t *head, int fd)
{
   node_t *current = head;
   if(current == NULL)
      return FALSE;
   while(current->next != NULL)
   {
      if(current->fd == fd)
         return TRUE;
      current = current->next;
   }
   if (current->fd == fd)
      return TRUE;
   return FALSE;
}

node_t* get_node(node_t *head, int fd)
{
   node_t *current = head;
   if(current == NULL)
      return NULL;
   while(current->next != NULL)
   {
      if(current->fd == fd)
         return current;
      current = current->next;
   }
   if (current->fd == fd)
      return current;
   return NULL;
}

void add_node(node_t **head, int fd)
{
   node_t *node = (node_t*)malloc(sizeof(node_t));
   node->fd = fd;
   memset(&(node->request), 0, sizeof(node->request));
   memset(&(node->response), 0, sizeof(node->response));
   node->reqoffset = 0;
   node->respoffset = 0;
   node->state = READ_STATE;
   node->next = *head;
   *head = node;
}

void remove_node(node_t **head, int fd)
{
   node_t *current = *head;
   node_t *prev = NULL;
   if(current == NULL)
      return;
   if(current->fd == fd)
   {
      *head = current->next;
      free(current);
      return;
   }
   prev = current;
   current = current->next;
   while(current->next != NULL)
   {
      if(current->fd == fd)
      {
         prev->next = current->next;
         free(current);
         return;
      }
      prev = current;
      current = current->next;
   }
   if (current->fd == fd)
   {
      prev->next = NULL;
      free(current);
      return;
   }
}

void free_list(node_t *head)
{
   node_t *current = head;
   if(current == NULL)
      return;
   node_t *next = head->next;
   while(next != NULL)
   {
      free(current);
      current = next;
      next = current->next;
   }
   free(current);
}

/* End linked list functions */

void server_exit()
{
   free_list(head);
   printf("Server exiting cleanly.\n");
   exit(EXIT_SUCCESS);
}

void sigint_handler(int sig)
{
   if(SIGINT == sig)
      server_exit();
}

void loginfo(char* msg)
{
   struct timeval now;
   double current_time;
   memset(&now, 0, sizeof(now));
   gettimeofday(&now, NULL);
   current_time = now.tv_sec + (now.tv_usec / 1000000.0);
   fprintf(stderr, "[TIME:%lf]LOG: %s\n", current_time, msg);
}

void ipv4_to_ipv6(char *ipv4, struct sockaddr_in6 *ipv6)
{
   uint8_t one, two, three, four;
   char ipv6_string[BUFSIZE];
   sscanf(ipv4, "%" SCNu8 ".%" SCNu8 ".%" SCNu8 ".%" SCNu8, &one, &two, &three, &four);
   sprintf(ipv6_string, "::ffff:%02x%02x:%02x%02x", one, two, three, four);
   inet_pton(AF_INET6, ipv6_string, ipv6->sin6_addr.s6_addr);
}

uint16_t parse_http(uint8_t *bytes)
{
   uint16_t flags = 0;
   char* request = strtok((char *)bytes, "\r\n");
   char* get = strtok(request, " ");
   char* url = strtok(NULL, " ");
   char* version = strtok(NULL, "");
   loginfo("Parsing request...");
   //Check for "GET"
   if(strcmp(get, "GET") != 0)
      flags |= GET_ERROR;

   //Check for a valid URL
   if(strcmp(url, "/json/implemented.json") == 0)
      flags |= IMPL_URL;
   else if(strcmp(url, "/json/about.json") == 0)
      flags |= ABOUT_URL;
   else if(strcmp(url, "/json/quit") == 0)
      flags |= QUIT_URL;
   else if(strcmp(url, "/json/status.json") == 0)
      flags |= STAT_URL;
   else if(strcmp(url, "/json/fortune") == 0)
      flags |= FORTUNE_URL;
   else
      flags |= URL_ERROR;

   //Check for version
   if(version == NULL)
      flags |= HTTP_0_9;
   else if(strcmp(version, "HTTP/1.0") == 0)
      flags |= HTTP_1_0;
   else if(strcmp(version, "HTTP/1.1") == 0)
      flags |= HTTP_1_1;
   else
      flags |= VERSION_ERROR;
   loginfo("Request parsed.");
   return flags;
}

// Returns the total size of the virtual address space for the running linux process
static long get_memory_usage_linux()
{
   // Variables to store all the contents of the stat file
   int pid, ppid, pgrp, session, tty_nr, tpgid;
   char comm[2048], state;
   unsigned int flags;
   unsigned long minflt, cminflt, majflt, cmajflt, vsize;
   unsigned long utime, stime;
   long cutime, cstime, priority, nice, num_threads, itrealvalue, rss;
   unsigned long long starttime;
   // Open the file
   FILE *stat = fopen("/proc/self/stat", "r");
   if (!stat) {
      perror("Failed to open /proc/self/stat");
      return 0;
   }
   // Read the statistics out of the file
   fscanf(stat, "%d%s%c%d%d%d%d%d%u%lu%lu%lu%lu"
      "%ld%ld%ld%ld%ld%ld%ld%ld%llu%lu%ld",
      &pid, comm, &state, &ppid, &pgrp, &session, &tty_nr,
      &tpgid, &flags, &minflt, &cminflt, &majflt, &cmajflt,
      &utime, &stime, &cutime, &cstime, &priority, &nice,
      &num_threads, &itrealvalue, &starttime, &vsize, &rss);
   fclose(stat);

   return vsize;
}

void send_response(int connection_socket)
{
   int numbytes;
   node_t* conninfo = get_node(head, connection_socket);
   loginfo("Sending response.");
   if((numbytes = write(connection_socket, (char*)(conninfo->response + conninfo->respoffset), strlen((char*)conninfo->response) - conninfo->respoffset)) < 0)
   {
      perror("Write failure");
      exit(EXIT_FAILURE);
   }
   conninfo->respoffset += numbytes;
   if (conninfo->respoffset == strlen((char *)conninfo->response))
   {
      conninfo->state = DONE_STATE;
      loginfo("Response sent.");
   }
}

void jsonfmt(char* json)
{
   int i = 0;
   int j = 0;
   int len = strlen(json);
   char new_json[BUFSIZE+1];
      
   if (json[i] == '"')
   {
      new_json[j++] = '\\';
      new_json[j++] = '"';
   }
   for(i=1; i<len; i++)
   {
      if(json[i] == '"' && json[i-1] != '\\')
      {
         new_json[j++] = '\\';
         new_json[j++] = '"';
      }
      else
         new_json[j++] = json[i];
   }
   new_json[j] = '\0';
   strcpy(json, new_json);
}

int gen_response(int connection_socket, uint16_t request_flags, struct timeval* start)
{
   char* version;
   char* data[BUFSIZE+1];
   node_t* conninfo = get_node(head, connection_socket);
   memset(data, 0, sizeof(char*)*BUFSIZE);

   loginfo("Generating request...");

   if(request_flags & HTTP_0_9)
      version = "HTTP/0.9";
   else if(request_flags & HTTP_1_0)
      version = "HTTP/1.0";
   else if(request_flags & HTTP_1_1)
      version = "HTTP/1.1";

   if(request_flags & FORTUNE_URL)
   {
      int fds[2];
      char fortunebuf[BUFSIZE+1];
      char* curl_args[] = {"curl", "https://helloacm.com/api/fortune/", NULL};
      pid_t pid;
      if(pipe(fds) < 0)
      {
         perror("Pipe failure");
         exit(EXIT_FAILURE);
      }
      if((pid = fork()) < 0)
      {
         perror("Fork failure");
         exit(EXIT_SUCCESS);
      }
      if(pid == 0)
      {
         close(fds[0]);
         dup2(fds[1], STDOUT_FILENO);
         execvp(curl_args[0], curl_args);
         perror("Exec failure");
         exit(EXIT_FAILURE);
      }
      else
      {
         close(fds[1]);
         if(read(fds[0], fortunebuf, BUFSIZE) < 0)
         {
            perror("Read failure");
            exit(EXIT_FAILURE);
         }
         close(fds[0]);
         wait(NULL);
         jsonfmt(fortunebuf);
         snprintf((char*)data, BUFSIZE, "{\"fortune\": \"%s\"}\n", fortunebuf);
      }
   }
   else if(request_flags & STAT_URL)
   {
      struct timeval now;
      struct timeval diff;
      struct timeval cpu_time;
      struct rusage usage;
      static unsigned long memory = 0;
      memset(&now, 0, sizeof(now));
      memset(&cpu_time, 0, sizeof(cpu_time));
      memset(&diff, 0, sizeof(diff));
      getrusage(RUSAGE_SELF, &usage);
      memory = get_memory_usage_linux();
      gettimeofday(&now, NULL);
      timersub(&now, start, &diff);
      timeradd(&(usage.ru_utime), &(usage.ru_stime), &cpu_time);
      double diff_microseconds = diff.tv_sec + (diff.tv_usec / 1000000.0);
      double cpu_microseconds = cpu_time.tv_sec + (cpu_time.tv_usec / 1000000.0);
      snprintf((char*)data, BUFSIZE, "{\"num_clients\": %d, "
             "\"num_requests\": %d, "
             "\"errors\": %d, "
             "\"uptime\": %lf, "
             "\"cpu_time\": %lf, "
             "\"memory_used\": %lu}\n", num_clients, num_requests, num_errors, diff_microseconds, cpu_microseconds, memory);
   }
   else if(request_flags & QUIT_URL)
   {
      strcpy((char*)data, "{\"result\": \"success\"}\n");
      snprintf((char*)(conninfo->response), sizeof(conninfo->response), "%s 200 OK\r\nContent-Type: application/json\r\n\r\n%s", version, (char*)data);
      write(connection_socket, (char*)(conninfo->response), strlen((char*)(conninfo->response)));
      server_exit();
   }
   else if(request_flags & ABOUT_URL)
      strcpy((char*)data, "{\"author\": \"Garrett DesRosiers\", "
             "\"email\": \"gdesrosi@calpoly.edu\", "
             "\"major\": \"CPE\"}\n");
   else if(request_flags & IMPL_URL)
      strcpy((char*)data, "[{\"feature\": \"about\", \"URL\": \"/json/about.json\"}, "
              "{\"feature\": \"quit\", \"URL\": \"/json/quit\"}, "
              "{\"feature\": \"status\", \"URL\": \"/json/status.json\"}, "
              "{\"feature\": \"fortune\", \"URL\": \"/json/fortune\"}]\n");

   loginfo("Adding request to connection...");
   snprintf((char*)(conninfo->response), sizeof(conninfo->response), "%s 200 OK\r\nContent-Type: application/json\r\n\r\n%s", version, (char*)data);
   return 0;
}

int read_request(int connection_socket, struct timeval *start)
{
   int numbytes;
   uint16_t request_flags;
   node_t* conninfo = get_node(head, connection_socket);
   if((numbytes = read(connection_socket, (conninfo->request + conninfo->reqoffset), (BUFSIZE - conninfo->reqoffset))) < 0)
   {
      perror("Read failure");
      exit(EXIT_FAILURE);
   }
   conninfo->reqoffset += numbytes;
   if (conninfo->request[conninfo->reqoffset - 1] == '\n')
   {
      conninfo->state = WRITE_STATE;
      request_flags = parse_http(conninfo->request);
      if(request_flags & HTTP_ERROR)
      {
         loginfo("Error parsing this HTTP request.");
         num_errors++;
         shutdown(connection_socket, SHUT_WR);
         return -1;
      }
      num_requests++;
      loginfo("Request parsed successfully.");
      gen_response(connection_socket, request_flags, start);
   }
   return 0;
}

int main(int argc, char* argv[])
{
   struct sigaction sa;
   struct sockaddr_in6 serveraddr;
   struct timeval start;
   int listen_socket, i;
   fd_set allfds, readfds, writefds;
   //char ipv6_string[BUFSIZE];
   socklen_t serveraddr_len;
   sa.sa_handler = sigint_handler;
   sa.sa_flags = 0;

   memset(&serveraddr, 0, sizeof(serveraddr));
   serveraddr.sin6_family = AF_INET6;
   serveraddr.sin6_port = htons(0);
   serveraddr.sin6_addr = in6addr_any;

   if(argc != 1 && argc != 2)
   {
      printf("Usage: %s [ip address]\n", argv[0]);
      return 1;
   }

   if(argc == 2)
   {
      if(strchr(argv[1], '.') != NULL)
         ipv4_to_ipv6(argv[1], &serveraddr);
      else
         inet_pton(AF_INET6, argv[1], &serveraddr.sin6_addr.s6_addr);

      //inet_pton(AF_INET, argv[1], &serveraddr.sin_addr.s_addr);
   }

   if (-1 == sigaction(SIGINT, &sa, NULL))
   {
      perror("Sigint Handler Failure");
      exit(EXIT_FAILURE);
   }

   listen_socket = socket(AF_INET6, SOCK_STREAM, 0);
   if(listen_socket < 0)
   {
      perror("Socket Creation Failure");
      exit(EXIT_FAILURE);
   }
   loginfo("Socket created.");

   if(bind(listen_socket, (struct sockaddr*) &serveraddr, sizeof(serveraddr)) < 0)
   {
      perror("Bind Failure");
      exit(EXIT_FAILURE);
   }
   loginfo("Socket bound to address.");

   serveraddr_len = sizeof(serveraddr);
   if (getsockname(listen_socket, (struct sockaddr*) &serveraddr, &serveraddr_len) < 0)
   {
      perror("getsockname");
      exit(EXIT_FAILURE);
   }
   //inet_ntop(AF_INET6, &(serveraddr.sin6_addr.s6_addr), ipv6_string, sizeof(ipv6_string));
   //printf("here %s\n", ipv6_string);

   printf("HTTP server is using TCP port %d\n", ntohs(serveraddr.sin6_port));
   printf("HTTPS server is using TCP port -1\n");
   fflush(stdout);

   if(listen(listen_socket, 100))
   {
      perror("Listen Failure");
      exit(EXIT_FAILURE);
   }
   loginfo("Socket listening.");

   FD_ZERO(&allfds);
   FD_SET(listen_socket, &allfds);
   gettimeofday(&start, NULL);
   while(1)
   {
      readfds = allfds;
      writefds = allfds;
      if(select(FD_SETSIZE, &readfds, &writefds, NULL, NULL) < 0)
      {
         perror("Select Failure");
         exit(EXIT_FAILURE);
      }

      for(i = 0; i < FD_SETSIZE; i++)
      {
         if(FD_ISSET(i, &readfds))
         {
            if(i == listen_socket)
            {
               int connect_socket = accept(listen_socket, NULL, NULL);
               if (connect_socket < 0)
               {
                  perror("Accept Failure");
                  exit(EXIT_FAILURE);
               }
               loginfo("Accepting new connection.");
               num_clients++;
               add_node(&head, connect_socket);
               FD_SET(connect_socket, &allfds);
            }
            else if(get_node(head, i)->state == READ_STATE)
            {
               //read as much as possible
               //do stuff w/connection
               if(read_request(i, &start) < 0)
               {
                  remove_node(&head, i);
                  FD_CLR(i, &allfds);
                  FD_CLR(i, &readfds);
                  FD_CLR(i, &writefds);
               }
            }
         }
         if(FD_ISSET(i, &writefds))
         {
            if(get_node(head, i)->state == WRITE_STATE)
            {
                //Write as much as possible
                send_response(i);
            }
            if(get_node(head, i)->state == DONE_STATE)
            {
                //Close connection
                remove_node(&head, i);
                shutdown(i, SHUT_WR);
                FD_CLR(i, &allfds);
            }
         }
      }
   }
   exit(EXIT_SUCCESS);
}
