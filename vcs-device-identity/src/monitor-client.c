#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

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
  
#define MAX_EVENTS 1024 /*Max. number of events to process at one go*/
#define LEN_NAME 1024 /*Assuming length of the filename won't exceed 16 bytes*/
#define EVENT_SIZE  ( sizeof (struct inotify_event) ) /*size of one event*/
#define BUF_LEN     ( MAX_EVENTS * ( EVENT_SIZE + LEN_NAME )) /*buffer to store the data of events*/
#define DHCP_LEASE_FOLDER "/tmp"
#define DHCP_LEASE_FILE_NAME "dhcp.leases"
#define DHCP_LEASE_FILE "/tmp/dhcp.leases"
#define DEVICE_SOCKET "/tmp/device_pipe"
#define MAX_LINE_LENGTH 256
#define DHCP_CLIENT_LOG "/usr/bin/dhcpclient.log"
#define CONFIG_FILE "/usr/bin/monitor-client.conf"

static  char s_url[256];
static char newConnectDeviceMsg[1024];

//#define HOST_BUCKETS 256

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

int searchList(char mac_addr_str[256]) {
    struct host_node *tmp = head;

    while (tmp != NULL) {
        if (strcmp((tmp->host).mac_addr_str, mac_addr_str) == 0) {
            return 1;
        }
        tmp = tmp->next;
    }
    return 0;
}

int updateDevice(char *mac){
    char line[1024];
    char tmp[256];
    char mac_tmp[256];
    char ip[256];
    char host_name[256];
    host_t nh;
    char buf[256];

    FILE *fp = fopen(DHCP_LEASE_FILE, "r");
    if (!fp) {
        printf("Open file %s failed\n", DHCP_LEASE_FILE);
        return;
    }

    while(fgets(line, sizeof(line), fp)){
        sscanf(line, "%s %s %s %s %s", tmp, mac_tmp, ip, host_name, tmp);
        if(strcmp(mac, mac_tmp) == 0) {
            strcpy(nh.ip_addr_str, ip);
            strcpy(nh.host_name, host_name);
            strcpy(nh.mac_addr_str, mac_tmp);

            //if (searchList(nh.mac_addr_str) == 0) {

            //    printf("New host info 1: mac: %s, ip: %s, host_name: %s, os: %s\n", nh.mac_addr_str, nh.ip_addr_str, nh.host_name, nh.os);
                query_os(nh.ip_addr_str, buf);
                strcpy(nh.os, buf);
                insertHost(nh);
            //}

            newConnectDeviceMsg[0] = '\0';
            sprintf(newConnectDeviceMsg, "Host name: %s, IP: %s, MAC: %s, OS: %s", nh.host_name, nh.ip_addr_str, nh.mac_addr_str, nh.os);
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_OPEN) {
    c->is_hexdumping = 1;
  } else if (ev == MG_EV_ERROR) {
    // On error, log error message
    MG_ERROR(("%p %s", c->fd, (char *) ev_data));
  } else if (ev == MG_EV_WS_OPEN) {
    // When websocket handshake is successful, send message
    char msg[4096] = {0,};
    //strcat(msg, "{\"id\":1,\"method\":\"update_host\",\"params\":[\"{bsbsbsb: kskjsk}\"]");
    sprintf(msg, "{\"id\":1,\"method\":\"client_connect\",\"params\":[\"{%s}\"]", newConnectDeviceMsg);
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
    mg_log_set(MG_LL_ERROR);  // Set log level
    c = mg_ws_connect(&mgr, s_url, fn, &done, NULL);     // Create client
    while (c && done == false) mg_mgr_poll(&mgr, 1000);  // Wait for echo
    mg_mgr_free(&mgr);                                   // Deallocate resources
    return ;
}
 


void query_os(char *ip, char *os) {
    u8 tmp[128];
    struct tm* t;
    strcpy(os, "*");
    
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
        printf("Can't connect to API socket.\n");
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

int getConfig(char * configFile) {
    FILE *fp = NULL;

    char line[MAX_LINE_LENGTH];
    char key[MAX_LINE_LENGTH];
    char value[MAX_LINE_LENGTH];

    // Open the configuration file
    fp = fopen(configFile, "r");
    if (fp == NULL) {
        printf("Failed to open the configuration file.\n");
        return -1;
    }

    // Read each line from the configuration file
    while (fgets(line, sizeof(line), fp)) {
        // Extract the key and value from the line
        sscanf(line, "%s %s", key, value);

        // Do something with the key-value pair
        printf("Key: %s, Value: %s\n", key, value);

        strcpy(s_url, value);

    }

    // Close the configuration file
    fclose(fp);

    return 0;

}

void monitorConnectedClient() {
    FILE *clientFile;
    char line[MAX_LINE_LENGTH];
    char ip_str[MAX_LINE_LENGTH];
    char mac_str[MAX_LINE_LENGTH];
    char tmp[MAX_LINE_LENGTH];

    // Open the configuration file
    
    clientFile = fopen(DHCP_CLIENT_LOG, "r");
    if (clientFile == NULL) {
        printf("Failed to open the dhcp client log file.\n");
        return;
    }

    // Get the initial position in the file
    fseek(clientFile, 0, SEEK_END);
    long filePos = ftell(clientFile);

    // Monitor the file for changes
    while (1) {
        // Check if the file has been modified
        fseek(clientFile, 0, SEEK_END);
        long newFilePos = ftell(clientFile);
        if (newFilePos != filePos) {
            // File has been modified, read new lines
            fseek(clientFile, filePos, SEEK_SET);
            ip_str[0] = '\0';
            mac_str[0] = '\0';

            while (fgets(line, sizeof(line), clientFile)) {
                sscanf(line, "%s %s %s %s %s %s %s %s %s %s", tmp, tmp, tmp, tmp, tmp, tmp, tmp, tmp, ip_str, mac_str);
                if (ip_str[0] == '\0' || mac_str[0] == '\0') {
                    printf("Read dhcp client log file error because wrong format.\n");
                }else {
                    printf("Detect new connected client - ip: %s, mac: %s \n", ip_str, mac_str);
                    if (updateDevice(mac_str)) {
                        notifyDevice();
                        newConnectDeviceMsg[0] = '\0';
                    }
                    
                }
            }

            // Update the file position
            filePos = newFilePos;
        }

        // Wait for a certain period before checking again
        sleep(1);
    }

    // Close the configuration file (never reached in this example)
    fclose(clientFile);

    return;
}
 
int main( int argc, char **argv ) {

    if (getConfig(CONFIG_FILE) != 0) {
        printf("Failed to get config from file!!!\n");
        return -1;
    }

    monitorConnectedClient();

    return 0;
}