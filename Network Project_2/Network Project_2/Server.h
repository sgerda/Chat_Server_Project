#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include<string>
#include <cstring>
#include <map>
#include <fstream>
#include <ctime>
#include <sstream>


struct ClientInfo {
	std::string hostName;
	SOCKET socket;
	std::string userName; // Add this to store the chosen username
	// Add any other client-related information you need
};


class Server
{

	//variables 
	SOCKET _ListenSocket;
	fd_set _master_set;
	fd_set _temp_set;

	//uint8_t _size = 255;

	std::string _command;
	std::map<std::string, std::string> _userDataBase;
	std::map<SOCKET, bool> _clientLoginStatus;
	std::map<SOCKET, std::string> _UsernameList;

	std::map<SOCKET, ClientInfo> _clientInfoMap;

	std::map<SOCKET, bool> _clientLogStatus;
	
	std::ofstream _publicMsgLogs;
	std::ofstream _commandLogs;


	//std::map<SOCKET, bool>

	char _SenBuff[255];
	char _RecvBuff[256];
	char _hostname[256];
	
	int _MaxClient = 0;
	int _activeClient = 0;
	

public:
	int init(uint16_t port, int MaxClient);
	int RunServer();
	int SendHelper(SOCKET client);
	int ReadHelper(SOCKET client);
	void CommandFunction(SOCKET client);
	bool Tokenizer(const std::string regis);
	bool ProcessLogin(SOCKET client, const std::string& arguments);
	void PrintLocalIPAddresses();
	void LogFiles(SOCKET client);
	void ProcessRegistration(SOCKET client, const std::string& arguments);
	void ProcessDMs(SOCKET client, const std::string& msg);
	void GetLog(SOCKET client);

	void ProcessLogout(SOCKET client);
	void HandleClientDisconnection(SOCKET client);

	void StartLogging();
	void StopLogging();
	void LogPublicMessage(const std::string& client, const std::string& message);
	void LogCommand(const std::string& client, const std::string& command);

	//functions given in the first lab.
	int tcp_send_whole(SOCKET s, const char* buffer, uint16_t len);
	int tcp_recv_whole(SOCKET s, char* buf, int len);

	//UDP Sender function
	void UDPBroadcast(uint16_t port);


};

