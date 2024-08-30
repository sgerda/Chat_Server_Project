#include <iostream>
#include <thread>
#include "Server.h"

int main()
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN );
    Server server;
    int32_t port = 0;
    int MaxClient = 0;
    int result = 0;

    std::cout << "Enter port number to be use\n";
    std::cin >> port;
    std::cout << "Please enter the amount of clients to accept\n";
    std::cin >> MaxClient;

    std::thread mythread(&Server::UDPBroadcast, &server, port);
    mythread.detach();
    

    WSADATA wsadata;
    WSAStartup(WINSOCK_VERSION, &wsadata);

    result = server.init(port, MaxClient);
}


