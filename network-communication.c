#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#include <time.h>
#include <ctype.h>
#include <stdint.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 50999
#define MAX_PEERS 100
#define MAX_POSTS 100
#define MAX_FOLLOWS 100
#define MAX_GROUPS 50
#define MAX_GROUP_MEMBERS 20
#define MAX_NOTIFICATIONS 100
#define TTL_DEFAULT 3600

char username[50];
char user_id[128];
char display_name[100];
char status[100] = "Online";

char followed_users[MAX_FOLLOWS][128];
int follow_count = 0;

typedef struct {
    char user_id[100];
    char display_name[100];
    char status[100];
    struct sockaddr_in address;
    int has_address;
} Peer;

Peer peer_list[MAX_PEERS];
int peer_count = 0;

typedef struct {
    char user_id[128];
    char display_name[100];
    char content[512];
    long timestamp;
    int liked;
} Post;

Post post_list[MAX_POSTS];
int post_count = 0;

typedef struct {
    char group_id[64];
    char group_name[100];
    char creator[128];
    char members[MAX_GROUP_MEMBERS][128];
    int member_count;
} Group;

Group group_list[MAX_GROUPS];
int group_count = 0;

typedef struct {
    char message[256];
    long expire_at;  
    int active;
} Notification;

Notification notifications[MAX_NOTIFICATIONS];
int notification_count = 0;

CRITICAL_SECTION status_lock;
CRITICAL_SECTION peer_lock;
CRITICAL_SECTION notif_lock;

void setup_udp_socket(SOCKET *sock) {
    *sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (*sock == INVALID_SOCKET) {
        printf("Failed to create socket: %d\n", WSAGetLastError());
        exit(1);
    }

    // Enable broadcast
    int broadcast = 1;
    setsockopt(*sock, SOL_SOCKET, SO_BROADCAST, (char *)&broadcast, sizeof(broadcast));

    int reuse = 1;
    setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));

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

long get_unix_timestamp() {
    return time(NULL);
}

char *generate_token(const char *user_id, const char *scope, int ttl) {
    static char token[256];
    long now = get_unix_timestamp();
    snprintf(token, sizeof(token), "%s|%ld|%s", user_id, now + ttl, scope);
    return token;
}

char *generate_message_id() {
    static char id[16];
    for (int i = 0; i < 8; ++i)
        sprintf(&id[i * 2], "%02x", rand() % 256);
    return id;
}

const char* get_user_id_from_display_name(const char* display_name) {
    EnterCriticalSection(&peer_lock);
    for (int i = 0; i < peer_count; ++i) {
        if (strcmp(peer_list[i].display_name, display_name) == 0) {
            LeaveCriticalSection(&peer_lock);
            return peer_list[i].user_id;
        }
    }
    LeaveCriticalSection(&peer_lock);
    return NULL;
}

void send_ack(SOCKET sock, const char *message_id, struct sockaddr_in *to) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer),
        "TYPE: ACK\n"
        "MESSAGE_ID: %s\n"
        "STATUS: RECEIVED\n\n",
        message_id);

    sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr *)to, sizeof(*to));
}

void update_peer(const char *uid, const char *name, const char *st, struct sockaddr_in *addr) {
    EnterCriticalSection(&peer_lock);
    for (int i = 0; i < peer_count; ++i) {
        if (strcmp(peer_list[i].user_id, uid) == 0) {
            strncpy(peer_list[i].display_name, name, sizeof(peer_list[i].display_name));
            strncpy(peer_list[i].status, st, sizeof(peer_list[i].status));
            if (addr) {
                peer_list[i].address = *addr;
                peer_list[i].has_address = 1;
            }
            LeaveCriticalSection(&peer_lock);
            return;
        }
    }
    if (peer_count < MAX_PEERS) {
        strncpy(peer_list[peer_count].user_id, uid, sizeof(peer_list[peer_count].user_id));
        strncpy(peer_list[peer_count].display_name, name, sizeof(peer_list[peer_count].display_name));
        strncpy(peer_list[peer_count].status, st, sizeof(peer_list[peer_count].status));
        peer_list[peer_count].address = *addr;
        peer_list[peer_count].has_address = 1;
        peer_count++;
    }

    LeaveCriticalSection(&peer_lock);
}

int is_followed(const char *uid) {
    for (int i = 0; i < follow_count; ++i) {
        if (strcmp(followed_users[i], uid) == 0) return 1;
    }
    return 0;
}

void follow_user(const char *uid) {
    if (!is_followed(uid) && follow_count < MAX_FOLLOWS) {
        strncpy(followed_users[follow_count++], uid, 128);

        // Lookup display name
        const char *name = uid;
        EnterCriticalSection(&peer_lock);
        for (int i = 0; i < peer_count; ++i) {
            if (strcmp(peer_list[i].user_id, uid) == 0) {
                name = peer_list[i].display_name;
                break;
            }
        }
        LeaveCriticalSection(&peer_lock);

        printf("Followed %s.\n", name);
    } else {
        printf("Already following or limit reached.\n");
    }
}

void unfollow_user(const char *uid) {
    const char *name = uid;
    EnterCriticalSection(&peer_lock);
    for (int i = 0; i < peer_count; ++i) {
        if (strcmp(peer_list[i].user_id, uid) == 0) {
            name = peer_list[i].display_name;
            break;
        }
    }
    LeaveCriticalSection(&peer_lock);

    for (int i = 0; i < follow_count; ++i) {
        if (strcmp(followed_users[i], uid) == 0) {
            for (int j = i; j < follow_count - 1; ++j) {
                strcpy(followed_users[j], followed_users[j + 1]);
            }
            follow_count--;
            printf("Unfollowed %s.\n", name);
            return;
        }
    }
    printf("Not currently following.\n");
}

void send_follow_packet(SOCKET sock, const char *target_user_id, int follow) {
    struct sockaddr_in target_addr = {0};
    int found = 0;

    EnterCriticalSection(&peer_lock);
    for (int i = 0; i < peer_count; ++i) {
        if (strcmp(peer_list[i].user_id, target_user_id) == 0) {
            target_addr = peer_list[i].address;
            found = peer_list[i].has_address;
            break;
        }
    }
    LeaveCriticalSection(&peer_lock);

    if (!found) {
        printf("Cannot send %s: unknown or offline peer.\n", follow ? "FOLLOW" : "UNFOLLOW");
        return;
    }

    char msg[512];
    char *msg_id = generate_message_id();
    char *token = generate_token(user_id, "follow", TTL_DEFAULT); // user_id|+TTL|follow
    long ts = get_unix_timestamp();

    snprintf(msg, sizeof(msg),
             "TYPE: %s\nMESSAGE_ID: %s\nFROM: %s\nTO: %s\nTIMESTAMP: %ld\nTOKEN: %s\n\n",
             follow ? "FOLLOW" : "UNFOLLOW",
             msg_id,
             user_id,
             target_user_id,
             ts,
             token);

    sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
    //printf("%s request sent to %s.\n", follow ? "FOLLOW" : "UNFOLLOW", target_user_id);
}

void send_ping(SOCKET sock) {
    struct sockaddr_in bcast;
    bcast.sin_family = AF_INET;
    bcast.sin_port = htons(PORT);
    bcast.sin_addr.s_addr = inet_addr("192.168.254.255"); // For testing
    //bcast.sin_addr.s_addr = inet_addr("255.255.255.255"); // Full broadcast address

    const char *ping = "TYPE: PING\nUSER_ID: you@192.168.1.100\n\n";

    char msg[512];
    snprintf(msg, sizeof(msg), "TYPE: PING\nUSER_ID: %s\n\n", user_id);
    sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&bcast, sizeof(bcast));
    //printf("[DISCOVERY] Sent PING.\n");
}

void send_profile(SOCKET sock) {
    struct sockaddr_in bcast;
    bcast.sin_family = AF_INET;
    bcast.sin_port = htons(PORT);
    bcast.sin_addr.s_addr = inet_addr("192.168.254.255"); // For testing
    //bcast.sin_addr.s_addr = inet_addr("255.255.255.255");

    char msg[512];
    snprintf(msg, sizeof(msg),"TYPE: PROFILE\nUSER_ID: %s\nDISPLAY_NAME: %s\nSTATUS: %s\n\n", user_id, display_name, status);

    sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&bcast, sizeof(bcast));
    //printf("[DISCOVERY] Sent PROFILE.\n");
}

void discovery_loop(void *arg) {
    SOCKET sock = *((SOCKET *)arg);
    while (1) {
        send_ping(sock);
        Sleep(500);
        send_profile(sock);
        Sleep(4500);
    }
}

void send_post(SOCKET sock, const char *content, int ttl) {
    char msg[1024];
    char *msg_id = generate_message_id();
    long ts = get_unix_timestamp();
    
    char token[256];
    snprintf(token, sizeof(token), "%s|%ld|broadcast", user_id, ts + ttl);

    snprintf(msg, sizeof(msg), "TYPE: POST\nUSER_ID: %s\nCONTENT: %s\nTTL: %d\nTIMESTAMP: %ld\nMESSAGE_ID: %s\nTOKEN: %s\n\n", user_id, content, ttl, ts, msg_id, token);

    EnterCriticalSection(&peer_lock);
    for (int i = 0; i < peer_count; ++i) {
        if (is_followed(peer_list[i].user_id) && peer_list[i].has_address) {
            sendto(sock, msg, strlen(msg), 0,
                   (struct sockaddr *)&peer_list[i].address, sizeof(peer_list[i].address));
        }
    }
    LeaveCriticalSection(&peer_lock);

    printf("Broadcast post sent to followers.\n");
}

void send_like_packet(SOCKET sock, Post *post, int like) {
    struct sockaddr_in to_addr = {0};
    int found = 0;

    EnterCriticalSection(&peer_lock);
    for (int i = 0; i < peer_count; ++i) {
        if (strcmp(peer_list[i].user_id, post->user_id) == 0) {
            to_addr = peer_list[i].address;
            found = peer_list[i].has_address;
            break;
        }
    }
    LeaveCriticalSection(&peer_lock);

    if (!found) {
        printf("Cannot send LIKE/UNLIKE: peer not found or no address.\n");
        return;
    }

    char msg[512];
    char *token = generate_token(user_id, "broadcast", TTL_DEFAULT);
    long ts_now = get_unix_timestamp();

    snprintf(msg, sizeof(msg), "TYPE: LIKE\nFROM: %s\nTO: %s\nPOST_TIMESTAMP: %ld\nACTION: %s\nTIMESTAMP: %ld\nTOKEN: %s\n\n", user_id, post->user_id, post->timestamp, like ? "LIKE" : "UNLIKE", ts_now, token);

    sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
    printf("You %s post from %s: \"%s\"\n", like ? "liked" : "unliked", post->display_name, post->content);
}

void send_dm(SOCKET sock, Peer *peer, const char *text) {
    if (!peer->has_address) {
        printf("Cannot send: Peer has no known address.\n");
        return;
    }

    long timestamp = get_unix_timestamp();
    char *token = generate_token(user_id, "chat", TTL_DEFAULT);
    char *msg_id = generate_message_id();

    char msg[1024];
    snprintf(msg, sizeof(msg), "TYPE: DM\nFROM: %s\nTO: %s\nCONTENT: %s\nTIMESTAMP: %ld\nMESSAGE_ID: %s\nTOKEN: %s\n\n", user_id, peer->user_id, text, timestamp, msg_id, token);
    /*
    printf("[DEBUG] Sending DM to: %s\n", peer->user_id);
    printf("[DEBUG] Packet:\n%s\n", msg);
    printf("[DEBUG] Peer address: %s:%d (has_address=%d)\n",
        inet_ntoa(peer->address.sin_addr),
        ntohs(peer->address.sin_port),
        peer->has_address);
    */

    sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&peer->address, sizeof(peer->address));
    printf("Sent DM to %s.\n", peer->display_name[0] ? peer->display_name : peer->user_id);
}

void send_group_create(SOCKET sock, const char *group_id, const char *group_name, const char *members_csv) {
    char msg[1024];
    char *token = generate_token(user_id, "group", 3600);
    long timestamp = get_unix_timestamp();

    if (group_count < MAX_GROUPS) {
        strncpy(group_list[group_count].group_id, group_id, sizeof(group_list[group_count].group_id));
        strncpy(group_list[group_count].group_name, group_name, sizeof(group_list[group_count].group_name));
        strncpy(group_list[group_count].creator, user_id, sizeof(group_list[group_count].creator));
        group_list[group_count].member_count = 0;

        char members_copy[512];
        strncpy(members_copy, members_csv, sizeof(members_copy));
        char *token_member = strtok(members_copy, ",");
        while (token_member && group_list[group_count].member_count < MAX_GROUP_MEMBERS) {
            strncpy(group_list[group_count].members[group_list[group_count].member_count],
                    token_member, 128);
            group_list[group_count].member_count++;
            token_member = strtok(NULL, ",");
        }

        group_count++;
    }

    snprintf(msg, sizeof(msg),
        "TYPE: GROUP_CREATE\nFROM: %s\nGROUP_ID: %s\nGROUP_NAME: %s\nMEMBERS: %s\nTIMESTAMP: %ld\nTOKEN: %s\n\n",
        user_id, group_id, group_name, members_csv, timestamp, token);

    // Send to all members
    EnterCriticalSection(&peer_lock);
    for (int i = 0; i < peer_count; ++i) {
        if (!peer_list[i].has_address) continue;
        if (strstr(members_csv, peer_list[i].user_id)) {
            sendto(sock, msg, strlen(msg), 0,
                   (struct sockaddr *)&peer_list[i].address, sizeof(peer_list[i].address));
        }
    }
    LeaveCriticalSection(&peer_lock);

    printf("Created group '%s' with members: %s\n", group_name, members_csv);
}

void send_group_update(SOCKET sock, const char *group_id, const char *add_list, const char *remove_list) {
    char msg[1024];
    long ts = get_unix_timestamp();
    char *token = generate_token(user_id, "group", TTL_DEFAULT);

    snprintf(msg, sizeof(msg), "TYPE: GROUP_UPDATE\nFROM: %s\nGROUP_ID: %s\nADD: %s\nREMOVE: %s\nTIMESTAMP: %ld\nTOKEN: %s\n\n", user_id, group_id, add_list, remove_list, ts, token);

    // Send to all current group members
    for (int i = 0; i < group_count; ++i) {
        if (strcmp(group_list[i].group_id, group_id) == 0) {
            for (int j = 0; j < group_list[i].member_count; ++j) {
                struct sockaddr_in addr = {0};
                int found = 0;
                const char *member = group_list[i].members[j];

                EnterCriticalSection(&peer_lock);
                for (int k = 0; k < peer_count; ++k) {
                    if (strcmp(peer_list[k].user_id, member) == 0) {
                        addr = peer_list[k].address;
                        found = peer_list[k].has_address;
                        break;
                    }
                }
                LeaveCriticalSection(&peer_lock);

                if (found) {
                    sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&addr, sizeof(addr));
                }
            }
            printf("Group \"%s\" membership update sent.\n", group_id);
            return;
        }
    }

    printf("Group \"%s\" not found locally.\n", group_id);
}

void send_group_message(SOCKET sock, const char *group_id, const char *content) {
    char msg[1024];
    long ts = get_unix_timestamp();
    char *token = generate_token(user_id, "group_message", TTL_DEFAULT);

    snprintf(msg, sizeof(msg),
        "TYPE: GROUP_MESSAGE\nFROM: %s\nGROUP_ID: %s\nCONTENT: %s\nTIMESTAMP: %ld\nTOKEN: %s\n\n",
        user_id, group_id, content, ts, token);

    for (int i = 0; i < group_count; ++i) {
        if (strcmp(group_list[i].group_id, group_id) == 0) {
            for (int j = 0; j < group_list[i].member_count; ++j) {
                const char *member = group_list[i].members[j];
                if (strcmp(member, user_id) == 0) continue; // skip self

                struct sockaddr_in addr = {0};
                int found = 0;

                EnterCriticalSection(&peer_lock);
                for (int k = 0; k < peer_count; ++k) {
                    if (strcmp(peer_list[k].user_id, member) == 0) {
                        addr = peer_list[k].address;
                        found = peer_list[k].has_address;
                        break;
                    }
                }
                LeaveCriticalSection(&peer_lock);

                if (found) {
                    sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&addr, sizeof(addr));
                }
            }
            printf("Group message sent to group \"%s\".\n", group_id);
            return;
        }
    }

    printf("Group \"%s\" not found locally.\n", group_id);
}

int is_group_member(const char *group_id, const char *uid) {
    for (int i = 0; i < group_count; ++i) {
        if (strcmp(group_list[i].group_id, group_id) == 0) {
            for (int j = 0; j < group_list[i].member_count; ++j) {
                if (strcmp(group_list[i].members[j], uid) == 0) return 1;
            }
        }
    }
    return 0;
}

void add_notification(const char *msg, int ttl_seconds) {
    long now = time(NULL);

    EnterCriticalSection(&notif_lock);
    for (int i = 0; i < MAX_NOTIFICATIONS; ++i) {
        if (!notifications[i].active) {
            strncpy(notifications[i].message, msg, sizeof(notifications[i].message));
            notifications[i].expire_at = now + ttl_seconds;
            notifications[i].active = 1;
            break;
        }
    }
    LeaveCriticalSection(&notif_lock);

    printf("\n\n%s\n\n", msg);
    printf("[L]ist peers | [D]M | [P]ost | [S]ee Posts | [G]roups | [Q]uit > ");
    fflush(stdout);
}

void add_group(const char *from, const char *gid, const char *gname, const char *members_csv, long ts) {
    if (group_count >= MAX_GROUPS) return;
    strncpy(group_list[group_count].group_id, gid, sizeof(group_list[group_count].group_id));
    strncpy(group_list[group_count].group_name, gname, sizeof(group_list[group_count].group_name));
    strncpy(group_list[group_count].creator, from, sizeof(group_list[group_count].creator));

    char *members = strdup(members_csv);
    char *token = strtok(members, ",");
    while (token && group_list[group_count].member_count < MAX_GROUP_MEMBERS) {
        strncpy(group_list[group_count].members[group_list[group_count].member_count++], token, 128);
        token = strtok(NULL, ",");
    }
    free(members);
    group_count++;

    if (is_group_member(gid, user_id)) {
        char notification[512];
        snprintf(notification, sizeof(notification), "You've been added to %s\n", gname);
        add_notification(notification, TTL_DEFAULT);
    }
}

void update_group(const char *gid, const char *add_csv, const char *remove_csv) {
    for (int i = 0; i < group_count; ++i) {
        if (strcmp(group_list[i].group_id, gid) == 0) {
            if (add_csv) {
                char *adds = strdup(add_csv);
                char *token = strtok(adds, ",");
                while (token && group_list[i].member_count < MAX_GROUP_MEMBERS) {
                    int exists = 0;
                    for (int j = 0; j < group_list[i].member_count; ++j) {
                        if (strcmp(group_list[i].members[j], token) == 0) { exists = 1; break; }
                    }
                    if (!exists) {
                        strncpy(group_list[i].members[group_list[i].member_count++], token, 128);
                    }
                    token = strtok(NULL, ",");
                }
                free(adds);
            }
            if (remove_csv) {
                char *rems = strdup(remove_csv);
                char *token = strtok(rems, ",");
                while (token) {
                    for (int j = 0; j < group_list[i].member_count; ++j) {
                        if (strcmp(group_list[i].members[j], token) == 0) {
                            for (int k = j; k < group_list[i].member_count - 1; ++k) {
                                strcpy(group_list[i].members[k], group_list[i].members[k+1]);
                            }
                            group_list[i].member_count--;
                            break;
                        }
                    }
                    token = strtok(NULL, ",");
                }
                free(rems);
            }
            if (is_group_member(gid, user_id)) {
                char notification[512];
                snprintf(notification, sizeof(notification), "The group \"%s\" member list was updated.\n", group_list[i].group_name, add_csv ? add_csv : "none", remove_csv ? remove_csv : "none");
                add_notification(notification, TTL_DEFAULT);
            }
            return;
        }
    }
}

void handle_group_message(const char *from, const char *gid, const char *content) {
    if (!is_group_member(gid, user_id)) return;
    char notification[512];
    snprintf(notification, sizeof(notification), "[%s] %s: %s", gid, from, content);
    add_notification(notification, TTL_DEFAULT);
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
            /*printf("\n[RECEIVED from %s:%d]\n%s\n",
                   inet_ntoa(sender.sin_addr),
                   ntohs(sender.sin_port),
                   buffer);*/

            char *type_line = strtok(buffer, "\n");
            if (!type_line) continue;

            if (strstr(type_line, "TYPE: PING")) {
                send_profile(sock);
            } else if (strstr(type_line, "TYPE: PROFILE")) {
                char *uid = NULL, *name = NULL, *st = NULL, *line;
                while ((line = strtok(NULL, "\n")) != NULL) {
                    if (strncmp(line, "USER_ID: ", 9) == 0) uid = line + 9;
                    else if (strncmp(line, "DISPLAY_NAME: ", 14) == 0) name = line + 14;
                    else if (strncmp(line, "STATUS: ", 8) == 0) st = line + 8;
                }

                if (uid && name && st && strcmp(uid, user_id) != 0) {
                    update_peer(uid, name, st, &sender);
                    send_profile(sock);
                }
            } else if (strstr(type_line, "TYPE: DM")) {
                char *from = NULL, *to = NULL, *content = NULL, *timestamp = NULL, *message_id = NULL, *token = NULL;
                char *line;

                while ((line = strtok(NULL, "\n")) != NULL) {
                    if (strncmp(line, "FROM: ", 6) == 0) from = line + 6;
                    else if (strncmp(line, "TO: ", 4) == 0) {
                        to = line + 4;
                        to[strcspn(to, "\r\n")] = '\0';} 
                    else if (strncmp(line, "CONTENT: ", 9) == 0)content = line + 9;
                    else if (strncmp(line, "TIMESTAMP: ", 11) == 0) timestamp = line + 11;
                    else if (strncmp(line, "MESSAGE_ID: ", 12) == 0) message_id = line + 12;
                    else if (strncmp(line, "TOKEN: ", 7) == 0) token = line + 7;
                    
                }

                /*
                printf("[DEBUG] user_id: '%s'\n", user_id);
                printf("[DEBUG] to:       '%s'\n", to);
                printf("[DEBUG] from:     '%s'\n", from ? from : "NULL");
                printf("[DEBUG] content:  '%s'\n", content ? content : "NULL");
                */

                if (to && strcmp(to, user_id) == 0 && from && content) {
                    const char *sender_display = from;
                    struct sockaddr_in sender_address;

                    EnterCriticalSection(&peer_lock);
                    for (int i = 0; i < peer_count; ++i) {
                        if (strcmp(peer_list[i].user_id, from) == 0) {
                            sender_display = peer_list[i].display_name[0] ? peer_list[i].display_name : from;
                            sender_address = peer_list[i].address;
                            break;
                        }
                    }

                    LeaveCriticalSection(&peer_lock);

                    // ACK 
                    send_ack(sock, message_id, &sender_address);

                    // For sending message to receiver
                    char notification[512];
                    snprintf(notification, sizeof(notification), "%s: %s", sender_display, content);
                    add_notification(notification, TTL_DEFAULT);
                } else {
                    printf("[DEBUG] DM not shown — TO mismatch or missing fields.\n");
                } 
            } else if (strstr(type_line, "TYPE: FOLLOW") || strstr(type_line, "TYPE: UNFOLLOW")) {
                char *from = NULL, *to = NULL, *msg_id = NULL, *token = NULL;
                char *line;

                while ((line = strtok(NULL, "\n")) != NULL) {
                    if (strncmp(line, "FROM: ", 6) == 0) from = line + 6;
                    else if (strncmp(line, "TO: ", 4) == 0) to = line + 4;
                    else if (strncmp(line, "MESSAGE_ID: ", 12) == 0) msg_id = line + 12;
                    else if (strncmp(line, "TOKEN: ", 7) == 0) token = line + 7;
                }

                if (from && to && strcmp(to, user_id) == 0) {
                    const char *display = from;

                    EnterCriticalSection(&peer_lock);
                    for (int i = 0; i < peer_count; ++i) {
                        if (strcmp(peer_list[i].user_id, from) == 0) {
                            if (peer_list[i].display_name[0]) {
                                display = peer_list[i].display_name;
                            }
                            break;
                        }
                    }
                    LeaveCriticalSection(&peer_lock);

                    char notification[512];

                    if (strstr(type_line, "TYPE: FOLLOW")) {
                        snprintf(notification, sizeof(notification), "%s has followed you", display);
                    } else {
                        snprintf(notification, sizeof(notification), "%s has unfollowed you", display);
                    }

                    add_notification(notification, TTL_DEFAULT);
                }
            } else if (strstr(type_line, "TYPE: POST")) {
                char *uid = NULL, *content = NULL, *line, *timestamp_str = NULL, *ttl_str = NULL, *message_id = NULL, *token = NULL;
                long ts = 0;
                int ttl = TTL_DEFAULT;

                while ((line = strtok(NULL, "\n")) != NULL) {
                    if (strncmp(line, "USER_ID: ", 9) == 0) uid = line + 9;
                    else if (strncmp(line, "CONTENT: ", 9) == 0) content = line + 9;
                    else if (strncmp(line, "TIMESTAMP: ", 11) == 0) timestamp_str = line + 11;
                    else if (strncmp(line, "TTL: ", 5) == 0) ttl_str = line + 5;
                    else if (strncmp(line, "MESSAGE_ID: ", 12) == 0) message_id = line + 12; 
                    else if (strncmp(line, "TOKEN: ", 7) == 0) token = line + 7;
                }

                if (uid && content && timestamp_str) {
                    ts = atol(timestamp_str);
                    if (ttl_str) ttl = atoi(ttl_str);

                    // Get display name from peer list
                    const char *disp = uid;
                    EnterCriticalSection(&peer_lock);
                    for (int i = 0; i < peer_count; ++i) {
                        if (strcmp(peer_list[i].user_id, uid) == 0) {
                            disp = peer_list[i].display_name;
                            break;
                        }
                    }
                    LeaveCriticalSection(&peer_lock);

                    if (post_count < MAX_POSTS) {
                        strncpy(post_list[post_count].user_id, uid, sizeof(post_list[post_count].user_id));
                        strncpy(post_list[post_count].content, content, sizeof(post_list[post_count].content));
                        strncpy(post_list[post_count].display_name, disp, sizeof(post_list[post_count].display_name));
                        post_list[post_count].timestamp = ts;
                        post_list[post_count].liked = 0;
                        post_count++;

                        char notification[512];
                        snprintf(notification, sizeof(notification), "[POST] %s: %s", disp, content);
                        add_notification(notification, ttl);
                    }
                }
            } else if (strstr(type_line, "TYPE: LIKE")) {
                char *from = NULL, *to = NULL, *action = NULL, *timestamp = NULL, *token = NULL;
                char *post_ts = NULL;
                char *line;

                while ((line = strtok(NULL, "\n")) != NULL) {
                    if (strncmp(line, "FROM: ", 6) == 0) from = line + 6;
                    else if (strncmp(line, "TO: ", 4) == 0) to = line + 4;
                    else if (strncmp(line, "POST_TIMESTAMP: ", 16) == 0) post_ts = line + 16;
                    else if (strncmp(line, "ACTION: ", 8) == 0) action = line + 8;
                    else if (strncmp(line, "TIMESTAMP: ", 11) == 0) timestamp = line + 11;
                    else if (strncmp(line, "TOKEN: ", 7) == 0) token = line + 7;
                }

                if (to && strcmp(to, user_id) == 0 && from && post_ts && action) {
                    long target_ts = atol(post_ts);
                    const char *from_disp = from;

                    EnterCriticalSection(&peer_lock);
                    for (int i = 0; i < peer_count; ++i) {
                        if (strcmp(peer_list[i].user_id, from) == 0) {
                            if (peer_list[i].display_name[0]) {
                                from_disp = peer_list[i].display_name;
                            }
                            break;
                        }
                    }
                    LeaveCriticalSection(&peer_lock);

                    // Find matching post to display content
                    const char *content = NULL;
                    for (int i = 0; i < post_count; ++i) {
                        if (post_list[i].timestamp == target_ts && strcmp(post_list[i].user_id, user_id) == 0) {
                            content = post_list[i].content;
                            break;
                        }
                    }

                    char notification[512];
                    snprintf(notification, sizeof(notification), "%s %s your post", from_disp, strcmp(action, "LIKE") == 0 ? "liked" : "unliked");
                    if (content) {
                        snprintf(notification + strlen(notification), sizeof(notification) - strlen(notification), ": \"%s\"", content);
                    } else {
                        snprintf(notification + strlen(notification), sizeof(notification) - strlen(notification), ".");
                    }
                    add_notification(notification, TTL_DEFAULT);
                }
            } else if (strstr(type_line, "TYPE: GROUP_CREATE")) {
                char *from = NULL, *gid = NULL, *gname = NULL, *members = NULL, *ts = NULL, *token = NULL, *line;

                while ((line = strtok(NULL, "\n")) != NULL) {
                    if (strncmp(line, "FROM: ", 6) == 0) from = line + 6;
                    else if (strncmp(line, "GROUP_ID: ", 10) == 0) gid = line + 10;
                    else if (strncmp(line, "GROUP_NAME: ", 12) == 0) gname = line + 12;
                    else if (strncmp(line, "MEMBERS: ", 9) == 0) members = line + 9;
                    else if (strncmp(line, "TIMESTAMP: ", 11) == 0) ts = line + 11;
                    else if (strncmp(line, "TOKEN: ", 7) == 0) token = line + 7;
                }

                if (from && gid && gname && members && ts) add_group(from, gid, gname, members, atol(ts));

            } else if (strstr(type_line, "TYPE: GROUP_UPDATE")) {
                char *from = NULL, *gid = NULL, *add = NULL, *remove = NULL, *timestamp = NULL, *token = NULL, *line;

                while ((line = strtok(NULL, "\n")) != NULL) {
                    if (strncmp(line, "FROM: ", 6) == 0) from = line + 6;
                    else if (strncmp(line, "GROUP_ID: ", 10) == 0) gid = line + 10;
                    else if (strncmp(line, "ADD: ", 5) == 0) add = line + 5;
                    else if (strncmp(line, "REMOVE: ", 8) == 0) remove = line + 8;
                    else if (strncmp(line, "TIMESTAMP: ", 11) == 0) timestamp = line + 11;
                    else if (strncmp(line, "TOKEN: ", 7) == 0) token = line + 7;
                }

                if (from && gid) update_group(gid, add, remove);

            } else if (strstr(type_line, "TYPE: GROUP_MESSAGE")) {
                char *from = NULL, *gid = NULL, *content = NULL, *timestamp = NULL, *token = NULL, *line;

                while ((line = strtok(NULL, "\n")) != NULL) {
                    if (strncmp(line, "FROM: ", 6) == 0) from = line + 6;
                    else if (strncmp(line, "GROUP_ID: ", 10) == 0) gid = line + 10;
                    else if (strncmp(line, "CONTENT: ", 9) == 0) content = line + 9;
                    else if (strncmp(line, "TIMESTAMP: ", 11) == 0) timestamp = line + 11;
                    else if (strncmp(line, "TOKEN: ", 7) == 0) token = line + 7;
                }

                if (from && gid && content) handle_group_message(from, gid, content);
            }
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

    const char *ip = inet_ntoa(name.sin_addr);
    printf("Your Local IP Address: %s\n", ip);

    snprintf(user_id, sizeof(user_id), "%s@%s", username, ip);
    user_id[strcspn(user_id, "\n")] = '\0';  
    //printf("[DEBUG] my user_id: %s\n", user_id); 

    closesocket(s);
}

void cleanup_notifications(void *arg) {
    while (1) {
        long now = time(NULL);

        EnterCriticalSection(&notif_lock);
        for (int i = 0; i < MAX_NOTIFICATIONS; ++i) {
            if (notifications[i].active && notifications[i].expire_at <= now) {
                notifications[i].active = 0;  // Expire it
            }
        }
        LeaveCriticalSection(&notif_lock);

        Sleep(1000); // Check every second
    }
}

void list_peers(SOCKET sock, int prompt_follow) {
    EnterCriticalSection(&peer_lock);

    printf("\nPeers\n");
    for (int i = 0; i < peer_count; ++i) {
        const char *uid = peer_list[i].user_id;
        int followed = is_followed(uid); 
        printf("[%d] %s - %s %s\n", i,
               peer_list[i].display_name,
               peer_list[i].status,
               followed ? "[FOLLOWING]" : "");
    }

    if (peer_count == 0) {
        printf("No peers discovered yet.\n");
    }
    printf("-------------------\n");

    if (!prompt_follow) {
        LeaveCriticalSection(&peer_lock);
        return;
    }

    printf("Enter peer number to follow/unfollow (or press Enter to skip): ");
    char input[10];
    fgets(input, sizeof(input), stdin);

    if (input[0] == '\n') {
        LeaveCriticalSection(&peer_lock);
        return;
    }

    int idx = atoi(input);
    if (idx >= 0 && idx < peer_count) {
        const char *uid = peer_list[idx].user_id;
        if (is_followed(uid)) {
            unfollow_user(uid);
            send_follow_packet(sock, uid, 0);  // send UNFOLLOW
        } else {
            follow_user(uid);
            send_follow_packet(sock, uid, 1);  // send FOLLOW
        }
    } else {
        printf("Invalid index.\n");
    }

    LeaveCriticalSection(&peer_lock);
}

void list_posts(SOCKET sock) {
    if (post_count == 0) {
        printf("No posts received.\n");
        return;
    }

    printf("\n--- Posts ---\n");
    for (int i = 0; i < post_count; ++i) {
        printf("[%d] %s: %s %s\n", i,
               post_list[i].display_name,
               post_list[i].content,
               post_list[i].liked ? "[LIKED]" : "");
    }

    printf("Select post number to like/unlike (or press Enter to skip): ");
    char input[10];
    fgets(input, sizeof(input), stdin);
    if (input[0] == '\n') return;

    int idx = atoi(input);
    if (idx >= 0 && idx < post_count) {
        post_list[idx].liked = !post_list[idx].liked;
        send_like_packet(sock, &post_list[idx], post_list[idx].liked);
    } else {
        printf("Invalid post number.\n");
    }
}

void input_loop(void *arg) {
    SOCKET sock = *((SOCKET *)arg);
    char cmd;

    while (1) {
        printf("\n[L]ist peers | [D]M | [P]ost | [S]ee Posts | [G]roups | [Q]uit > ");
        cmd = getchar();
        getchar(); 

        if (cmd == 'L' || cmd == 'l') {
            list_peers(sock, 1);
        } else if (cmd == 'D' || cmd == 'd') {
            list_peers(sock, 0);
            printf("Enter peer number to message: ");
            int idx;
            scanf("%d", &idx);
            getchar();  

            EnterCriticalSection(&peer_lock);
            if (idx >= 0 && idx < peer_count) {
                char message[256];
                printf("Enter message: ");
                fgets(message, sizeof(message), stdin);
                message[strcspn(message, "\n")] = '\0';

                send_dm(sock, &peer_list[idx], message);
            } else {
                printf("Invalid peer number.\n");
            }
            LeaveCriticalSection(&peer_lock);
        } else if (cmd == 'P' || cmd == 'p') {
            char post[512];
            printf("Enter post content: ");
            fgets(post, sizeof(post), stdin);
            post[strcspn(post, "\n")] = '\0';

            int ttl = TTL_DEFAULT;  // default TTL
            printf("Enter TTL in seconds (or press Enter for default): ");
            char ttl_input[10];
            fgets(ttl_input, sizeof(ttl_input), stdin);
            if (ttl_input[0] != '\n') ttl = atoi(ttl_input);

            send_post(sock, post, ttl);
        } else if (cmd == 'S' || cmd == 's') {
            list_posts(sock);
        } else if (cmd == 'G' || cmd == 'g') {
            printf("[1] Create Group\n");
            printf("[2] Update Group\n");
            printf("[3] Send Group Message\n");
            printf("Choose an option: ");
            char subcmd = getchar(); 
            getchar();

            if (subcmd == '1') {
                char group_id[64], group_name[64], input[512], members[1024] = "";

                printf("Enter Group ID (e.g. trip2025): ");
                fgets(group_id, sizeof(group_id), stdin);
                group_id[strcspn(group_id, "\n")] = '\0';

                printf("Enter Group Name: ");
                fgets(group_name, sizeof(group_name), stdin);
                group_name[strcspn(group_name, "\n")] = '\0';

                printf("Enter display names to add (comma-separated): ");
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = '\0';

                // Start member list with the creator
                strcpy(members, user_id);

                char *token = strtok(input, ",");
                while (token) {
                    while (*token == ' ') token++; 
                    const char *uid = get_user_id_from_display_name(token);
                    if (uid && strcmp(uid, user_id) != 0) {
                        strcat(members, ",");
                        strcat(members, uid);
                    } else if (!uid) {
                        printf("Display name '%s' not found. Skipping.\n", token);
                    }
                    token = strtok(NULL, ",");
                }

                send_group_create(sock, group_id, group_name, members);
            } else if (subcmd == '2') {
                char group_id[64], add_input[512], remove_input[512];
                char add_list[1024] = "", remove_list[1024] = "";

                printf("Enter Group ID to update: ");
                fgets(group_id, sizeof(group_id), stdin);
                group_id[strcspn(group_id, "\n")] = '\0';

                printf("Enter display names to ADD (comma-separated, or leave blank): ");
                fgets(add_input, sizeof(add_input), stdin);
                add_input[strcspn(add_input, "\n")] = '\0';

                char *token = strtok(add_input, ",");
                while (token) {
                    while (*token == ' ') token++;
                    const char *uid = get_user_id_from_display_name(token);
                    if (uid) {
                        if (add_list[0]) strcat(add_list, ",");
                        strcat(add_list, uid);
                    } else {
                        printf("Display name '%s' not found, skipping.\n", token);
                    }
                    token = strtok(NULL, ",");
                }

                printf("Enter display names to REMOVE (comma-separated, or leave blank): ");
                fgets(remove_input, sizeof(remove_input), stdin);
                remove_input[strcspn(remove_input, "\n")] = '\0';

                token = strtok(remove_input, ",");
                while (token) {
                    while (*token == ' ') token++;
                    const char *uid = get_user_id_from_display_name(token);
                    if (uid) {
                        if (remove_list[0]) strcat(remove_list, ",");
                        strcat(remove_list, uid);
                    } else {
                        printf("Display name '%s' not found, skipping.\n", token);
                    }
                    token = strtok(NULL, ",");
                }

                send_group_update(sock, group_id, add_list, remove_list);
            } else if (subcmd == '3') {
                char gid[50], content[512];
                printf("Enter group ID: ");
                fgets(gid, sizeof(gid), stdin); gid[strcspn(gid, "\n")] = 0;

                printf("Enter message: ");
                fgets(content, sizeof(content), stdin); content[strcspn(content, "\n")] = 0;

                send_group_message(sock, gid, content);
            } else {
                printf("Invalid group option.\n");
            }
        } else if (cmd == 'Q' || cmd == 'q') {
            printf("Disconnecting...\n");
            closesocket(sock);
            WSACleanup();
            exit(0);
        }
    }
}

int main() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }

    InitializeCriticalSection(&peer_lock);
    InitializeCriticalSection(&status_lock);
    InitializeCriticalSection(&notif_lock); 

    SOCKET sock;
    setup_udp_socket(&sock);

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = '\0';

    printf("Enter display name: ");
    fgets(display_name, sizeof(display_name), stdin);
    display_name[strcspn(display_name, "\n")] = '\0';

    printf("Enter status: ");
    fgets(status, sizeof(status), stdin);
    status[strcspn(status, "\n")] = '\0';

    print_own_ip();

    _beginthread(cleanup_notifications, 0, NULL);
    _beginthread(discovery_loop, 0, &sock);
    _beginthread(input_loop, 0, &sock); 
    
    receive_messages(sock);  

    closesocket(sock);
    WSACleanup();
    return 0;
}

