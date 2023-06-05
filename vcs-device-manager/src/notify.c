#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <limits.h>
#include <unistd.h>

#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "types.h"
#include "config.h"
#include "alloc-inl.h"
#include "debug.h"
#include "api.h"
#include "mongoose.h"

static const char *s_url = "ws://35.213.167.30:8081/websocket";
  
#define MAX_EVENTS 1024 /*Max. number of events to process at one go*/
#define LEN_NAME 1024 /*Assuming length of the filename won't exceed 16 bytes*/
#define EVENT_SIZE  ( sizeof (struct inotify_event) ) /*size of one event*/
#define BUF_LEN     ( MAX_EVENTS * ( EVENT_SIZE + LEN_NAME )) /*buffer to store the data of events*/
#define DHCP_LEASE_FOLDER "/tmp"
#define DHCP_LEASE_FILE_NAME "dhcp.leases"
#define DHCP_LEASE_FILE "/tmp/dhcp.leases"
#define DEVICE_SOCKET "/tmp/device_pipe"

#define HOST_BUCKETS 256

typedef struct host {
    char host_name[256];
    char ip_addr_str[256];
    char mac_addr_str[256];
    char os[256];
}host_t;

struct host_node {
    host_t host;
    struct host_node *next;
};

struct host_node *head = NULL;


static void parse_addr4(char* str, u8* ret) {

  u32 a1, a2, a3, a4;

  if (sscanf(str, "%u.%u.%u.%u", &a1, &a2, &a3, &a4) != 4)
    FATAL("Malformed IPv4 address.");

  if (a1 > 255 || a2 > 255 || a3 > 255 || a4 > 255)
    FATAL("Malformed IPv4 address.");

  ret[0] = a1;
  ret[1] = a2;
  ret[2] = a3;
  ret[3] = a4;

}


/* Parse IPv6 address into a buffer. */

static void parse_addr6(char* str, u8* ret) {

  u32 seg = 0;
  u32 val;

  while (*str) {

    if (seg == 8) FATAL("Malformed IPv6 address (too many segments).");

    if (sscanf((char*)str, "%x", &val) != 1 ||
        val > 65535) FATAL("Malformed IPv6 address (bad octet value).");

    ret[seg * 2] = val >> 8;
    ret[seg * 2 + 1] = val;

    seg++;

    while (isxdigit(*str)) str++;
    if (*str) str++;

  }

  if (seg != 8) FATAL("Malformed IPv6 address (don't abbreviate).");

}

void printList(){
    struct host_node *p = head;

    //start from beginning
    while (p != NULL) {
        printf("host_name: %s, ip: %s, mac: %s, os: %s \n", (p->host).host_name, (p->host).ip_addr_str, (p->host).mac_addr_str, (p->host).os);
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

void updateDevice(){
    char line[1024];
    char tmp[256];
    host_t nh;
    char buf[256];

    FILE *fp = fopen(DHCP_LEASE_FILE, "r");
    if (!fp) {
        printf("Open file %s failed\n", DHCP_LEASE_FILE);
        return;
    }

    while(fgets(line, sizeof(line), fp)){
        sscanf(line, "%s %s %s %s %s", tmp, nh.mac_addr_str, nh.ip_addr_str, nh.host_name, tmp);
        if (searchList(nh.ip_addr_str) == 0) {

            query_os(nh.ip_addr_str, buf);
            strcpy(nh.os, buf);

            insertHost(nh);
        }
    }

    

    fclose(fp);

    printList();

    return;
}

static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_OPEN) {
    c->is_hexdumping = 1;
  } else if (ev == MG_EV_ERROR) {
    // On error, log error message
    MG_ERROR(("%p %s", c->fd, (char *) ev_data));
  } else if (ev == MG_EV_WS_OPEN) {
    // When websocket handshake is successful, send message
    char host_list[4096] = {0,};
    char msg[4096] = {0,};

    strcat(msg, "{\"id\":1,\"method\":\"update_host\",\"params\":[");
    struct host_node *p = head;

    //start from beginning
    
    if (p != NULL) {
        sprintf(host_list, "\"host_name - %s, ip - %s, mac - %s, os - %s \"", (p->host).host_name, (p->host).ip_addr_str, (p->host).mac_addr_str, (p->host).os);
        //p = p->next;
    }

    strcat(msg, host_list);
    

    strcat(msg, "]");

    printf("Msg: %s\n", msg);

    //strcpy(msg, "{\"id\":1,\"method\":\"domain_query\",\"params\":[\"abc.top\"]}");
    mg_ws_send(c, msg, strlen(msg), WEBSOCKET_OP_TEXT);
  } else if (ev == MG_EV_WS_MSG) {
    // When we get echo response, print it
    struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
    printf("GOT ECHO REPLY: [%.*s]\n", (int) wm->data.len, wm->data.ptr);
  }

  if (ev == MG_EV_ERROR || ev == MG_EV_CLOSE || ev == MG_EV_WS_MSG) {
    *(bool *) fn_data = true;  // Signal that we're done
  }
}

void notifyDevice() {
    struct mg_mgr mgr;        // Event manager
    bool done = false;        // Event handler flips it to true
    struct mg_connection *c;  // Client connection
    mg_mgr_init(&mgr);        // Initialise event manager
    mg_log_set(MG_LL_DEBUG);  // Set log level
    c = mg_ws_connect(&mgr, s_url, fn, &done, NULL);     // Create client
    while (c && done == false) mg_mgr_poll(&mgr, 1000);  // Wait for echo
    mg_mgr_free(&mgr);                                   // Deallocate resources
    return ;
}
 
void get_event (int fd) {
    char buffer[BUF_LEN];
    int length, i = 0;
 
    length = read( fd, buffer, BUF_LEN );  
    if ( length < 0 ) {
        perror( "read" );
    }  
  
    while ( i < length ) {
        struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];
        if ( event->len ) {
            if ( event->mask & IN_CREATE) {
                if (event->mask & IN_ISDIR)
                    printf( "The directory %s was Created.\n", event->name );       
                else
                    printf( "The file %s was Created with WD %d\n", event->name, event->wd );       
            }
            
            if ( event->mask & IN_MODIFY) {
                if (event->mask & IN_ISDIR)
                    printf( "The directory %s was modified.\n", event->name );       
                else {
                    printf( "The file %s was modified with WD %d\n", event->name, event->wd );
                    if (strcmp(event->name, DHCP_LEASE_FILE_NAME) == 0) {
                        sleep(8);
                        updateDevice();
                        notifyDevice();
                    }
                }
                           
            }
            
            if ( event->mask & IN_DELETE) {
                if (event->mask & IN_ISDIR)
                    printf( "The directory %s was deleted.\n", event->name );       
                else
                    printf( "The file %s was deleted with WD %d\n", event->name, event->wd );       
            }  
            i += EVENT_SIZE + event->len;
        }
    }
}
void query_os(char *ip, char *os) {
    u8 tmp[128];
    struct tm* t;
    strcpy(os, "?");
    
    static struct p0f_api_query q;
    static struct p0f_api_response r;
    
    static struct sockaddr_un sun;
    
    s32  sock;
    time_t ut;

    q.magic = P0F_QUERY_MAGIC;

    if (strchr(ip, ':')) {
        parse_addr6(ip, q.addr);
        q.addr_type = P0F_ADDR_IPV6;
    }else {
        parse_addr4(ip, q.addr);
        q.addr_type = P0F_ADDR_IPV4;
    }

    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) 
    {
        printf("Call to socket() failed.");
        return;
    }

    sun.sun_family = AF_UNIX;

    if (strlen(DEVICE_SOCKET) >= sizeof(sun.sun_path)) {
        printf("API socket filename is too long for sockaddr_un (blame Unix).");
        return;
    }
        
    
    strcpy(sun.sun_path, DEVICE_SOCKET);

    if (connect(sock, (struct sockaddr*)&sun, sizeof(sun))){
        printf("Can't connect to API socket.");
        return;
    }
        

    if (write(sock, &q, sizeof(struct p0f_api_query)) !=
        sizeof(struct p0f_api_query)) {
            printf("Short write to API socket.");
            return ;
        }

    if (read(sock, &r, sizeof(struct p0f_api_response)) !=
        sizeof(struct p0f_api_response)) {
            printf("Short read from API socket.");
            return;
            }
  
    close(sock);

    if (r.magic != P0F_RESP_MAGIC) {
        printf("Bad response magic (0x%08x).\n", r.magic);
        return;
    }
    

    if (r.status == P0F_STATUS_BADQUERY) {
        printf("Did not understand the query.\n");
        return;
    }
        

    if (r.status == P0F_STATUS_NOMATCH) {
        SAYF("No matching host in cache. That's all we know.\n");
        return ;
    }

    if (!r.os_name[0]){
        printf("Detected OS   = ???\n");
        return ;
    }else {
        sprintf(os, "%s %s",r.os_name, r.os_flavor);
        printf(os);
        return;
    }
    return;
}
 
int main( int argc, char **argv ) {
    int wd, fd;
  
    fd = inotify_init();
    if ( fd < 0 ) {
        perror( "Couldn't initialize inotify");
    }
  
    wd = inotify_add_watch(fd, DHCP_LEASE_FOLDER, IN_CREATE | IN_MODIFY | IN_DELETE); 
    if (wd == -1) {
        printf("Couldn't add watch to %s\n",DHCP_LEASE_FOLDER);
    } else {
        printf("Watching:: %s\n",DHCP_LEASE_FOLDER);
    }
  
    /* do it forever*/
    while(1) {
        get_event(fd); 
    } 
 
    /* Clean up*/
    inotify_rm_watch( fd, wd );
    close( fd );
    
    return 0;
}