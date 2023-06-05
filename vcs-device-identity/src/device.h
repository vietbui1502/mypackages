typedef struct host {
    char host_name[256];
    char ip_addr_str[256];
    char mac_addr_str[256];
}host_t;

struct host_node {
    host_t host;
    struct host_node *next;
};

void printList();
void insertHost(host_t host);
int searchList(char ip_add_str[256]);
void *watch_dhcpleasefile();
void *myThreadFun();