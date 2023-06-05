#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <limits.h>
#include <unistd.h>


#include "device.h"

#define MAX_EVENTS 1024 /*Max. number of events to process at one go*/
#define LEN_NAME 1024 /*Assuming length of the filename won't exceed 16 bytes*/
#define EVENT_SIZE  ( sizeof (struct inotify_event) ) /*size of one event*/
#define BUF_LEN     ( MAX_EVENTS * ( EVENT_SIZE + LEN_NAME )) /*buffer to store the data of events*/
#define DHCP_LEASE_FOLDER "/tmp"
#define DHCP_LEASE_FILE "dhcp.leases"

struct host_node *head = NULL;
struct host_node *current = NULL;

void printList(){
    struct host_node *p = head;

    //start from beginning
    while (p != NULL) {
        printf("host_name: %s, ip: %s, mac: %s \n", (p->host).host_name, (p->host).ip_addr_str, (p->host).mac_addr_str);
        p = p->next;
    }
}

void insertHost(host_t host){
    struct host_node *nh = (struct host_node*)malloc(sizeof(struct host_node));
    nh->host = host;
    nh->next = NULL;

    if (head == NULL){
        head = nh;
        return;
    }

    struct host_node *node = head;

    while(node->next != NULL) {
        node = node->next;
    }

    node->next = nh;
    return;
}

int searchList(char ip_add_str[256]) {
    struct host_node *tmp = head;

    while (tmp != NULL) {
        if (strcmp((tmp->host).ip_addr_str, ip_add_str) == 0) {
            return 1;
        }
        tmp = tmp->next;
    }
    return 0;
}

void *watch_dhcpleasefile(){
    int wd, fd;
    char buffer[BUF_LEN];
    int length, i = 0;
  
    fd = inotify_init();
    if ( fd < 0 ) {
        printf( "Couldn't initialize inotify\n");
    }
  
    wd = inotify_add_watch(fd, DHCP_LEASE_FOLDER, IN_CREATE | IN_MODIFY | IN_DELETE); 
    if (wd == -1) {
        printf("Couldn't add watch to %s\n",DHCP_LEASE_FOLDER);
    } else {
        printf("Watching:: %s\n",DHCP_LEASE_FOLDER);
    }

    /* do it forever*/
    while(1) {
        //get_event(fd); 
        sleep(1);
        printf("pre-check\n");
 
        length = read( fd, buffer, BUF_LEN );  
        if ( length < 0 ) {
            printf( "Read error!!!" );
        }

        while ( i < length ) {
            printf("ck 1\n");
            struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];
            if ( event->len ) {
                printf("ck 2\n");
                if ( event->mask & IN_CREATE) {
                    printf("ck 3\n");
                    if (event->mask & IN_ISDIR)
                        printf( "The directory %s was Created.\n", event->name );       
                    else
                    printf( "The file %s was Created with WD %d\n", event->name, event->wd );       
                }
            
            if ( event->mask & IN_MODIFY) {
                printf("ck 4\n");
                if (event->mask & IN_ISDIR)
                    printf( "The directory %s was modified.\n", event->name );       
                else {
                    printf( "The file %s was modified with WD %d\n", event->name, event->wd );
                }
                           
            }
            
            if ( event->mask & IN_DELETE) {
                printf("ck 5\n");
                if (event->mask & IN_ISDIR)
                    printf( "The directory %s was deleted.\n", event->name );       
                else
                    printf( "The file %s was deleted with WD %d\n", event->name, event->wd );       
                }  
                i += EVENT_SIZE + event->len;
            }
        }
    } 
 
    /* Clean up*/
    inotify_rm_watch(fd, wd);
    close(fd);
    
    return NULL;
}

void *myThreadFun()
{
    while (1) {
        sleep(1);
        printf("Printing GeeksQuiz from Thread \n");
    }
    
    return NULL;
}