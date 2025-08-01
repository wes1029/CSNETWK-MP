#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 50999

void setup_udp_socket(SOCKET *sock) {
    *sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (*sock == INVALID_SOCKET) {
        printf("Failed to create socket: %d\n", WSAGetLastError());
        exit(1);
    }

    // Enable broadcast
    int broadcast = 1;
    setsockopt(*sock, SOL_SOCKET, SO_BROADCAST, (char *)&broadcast, sizeof(broadcast));

    // Bind to port 50999
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(PORT);

    if (bind(*sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
        printf("Bind failed: %d\n", WSAGetLastError());
        exit(1);
    }

    printf("UDP socket bound to port %d.\n", PORT);
}

void send_ping(SOCKET sock) {
    struct sockaddr_in bcast;
    bcast.sin_family = AF_INET;
    bcast.sin_port = htons(PORT);
    bcast.sin_addr.s_addr = inet_addr("255.255.255.255"); // Full broadcast address

    const char *ping = "TYPE: PING\nUSER_ID: you@192.168.1.100\n\n";

    sendto(sock, ping, strlen(ping), 0, (struct sockaddr *)&bcast, sizeof(bcast));
    printf("Sent PING broadcast.\n");
}

void receive_messages(SOCKET sock) {
    struct sockaddr_in sender;
    int sender_len = sizeof(sender);
    char buffer[2048];

    printf("Listening for incoming LSNP messages...\n");

    while (1) {
        int len = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                           (struct sockaddr *)&sender, &sender_len);
        if (len > 0) {
            buffer[len] = '\0';
            printf("\nReceived from %s:%d\n%s\n",
                   inet_ntoa(sender.sin_addr),
                   ntohs(sender.sin_port),
                   buffer);
        }
    }
}

void print_own_ip() {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(80);
    dest.sin_addr.s_addr = inet_addr("8.8.8.8");

    connect(s, (struct sockaddr *)&dest, sizeof(dest));

    struct sockaddr_in name;
    int namelen = sizeof(name);
    getsockname(s, (struct sockaddr *)&name, &namelen);

    char ipstr[INET_ADDRSTRLEN];
    DWORD ipstr_len = INET_ADDRSTRLEN;
    WSAAddressToStringA((LPSOCKADDR)&name, sizeof(name), NULL, ipstr, &ipstr_len);
    printf("Your Local IP Address: %s\n", ipstr);

    closesocket(s);
}

int main() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }

    SOCKET sock;
    setup_udp_socket(&sock);

    print_own_ip();

    send_ping(sock);

    receive_messages(sock);  // Never returns

    closesocket(sock);
    WSACleanup();
    return 0;
}
