#define _CRT_SECURE_NO_WARNINGS                
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib,"Ws2_32.lib")

#include <iostream>
#include "Server.h"
#include <thread>
#include <chrono>




//ERROR RETURN NOTE :
/* 
* NOTE FOR TOMORROW CREATE THE GET LOG AND FIX THE ~SEND AND LOGGIN COMMANDS
* 
*	0 =RETURN VALUE WAS GOOD.
*	-1 = IF THE CREATION OF THE SOCKET FAILED.
*	-2 = ERROR BINDING THE SOCKET
*	-3 = ERROR LISTENING FOR SOCKETS.
*	
*	-10 = RUNSERVER RETURNS AN ERROR. FAILED TO DO IT'S JOB.
*/


void Server::UDPBroadcast(uint16_t port) {
	SOCKET UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	int optVal = 1;
	setsockopt(UDPSocket, SOL_SOCKET, SO_BROADCAST, (const char*)&optVal, sizeof(optVal));

	sockaddr_in BroadCastAddr;
	BroadCastAddr.sin_family = AF_INET;
	BroadCastAddr.sin_addr.S_un.S_addr = INADDR_BROADCAST;
	BroadCastAddr.sin_port = htons(port);

	const char* message = "Broadcast message";
	while (true) {
		sendto(UDPSocket, message, strlen(message), 0, (sockaddr*)&BroadCastAddr, sizeof(BroadCastAddr));
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	closesocket(UDPSocket);
}

//first function that get's call.
int Server::init(uint16_t port, int MaxClient)
{


	//Listening socket creation.
	_ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	//error check for listening creation.
	if (_ListenSocket == INVALID_SOCKET) {
		std::cout << "Error happaned creating the socket: " << WSAGetLastError() << '\n';

		return -1;
	}

	//binding process
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.S_un.S_addr = INADDR_ANY;
	serverAddr.sin_port = htons(port); //The port of number is set by the server personnel.

	//binding the listening socket
	int result = bind(_ListenSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr));
	//error check the binding process.
	if (result == SOCKET_ERROR) {
		std::cout << "Error happaned during binding the listening socket: " << WSAGetLastError() << '\n';
		return -2;
	}

	//listening  socket
	result = listen(_ListenSocket, MaxClient); //Maxclient(max# of clients set by server personnel)
	if (result == SOCKET_ERROR) {
		std::cout << "Error happaned listening for max number of clients: " << WSAGetLastError() << '\n';
		return -3;
	}

	//print local addresses
	PrintLocalIPAddresses();

	//fd_set initiation
	FD_ZERO(&_master_set);
	FD_SET(_ListenSocket, &_master_set);
	_MaxClient = MaxClient; //max number of clients set to private veriable.

	if (RunServer() == -10) {
		std::cout << "Error happaned in the RunServer Function: " << WSAGetLastError() << '\n';
		return -10;
	}

	
	//if everything is good then return 0 
	return 0;
}

int Server::RunServer()
{
	FD_ZERO(&_temp_set);

	//infinite loop that runs the server
	while (true) {

		//copy master to temp set
		_temp_set = _master_set;
		int masterSetCount = _master_set.fd_count;
		

		int ready_fd = select(0, &_temp_set, NULL, NULL, NULL); //the ready_set is the amount of socket ready to communicate
		if (ready_fd == SOCKET_ERROR) {
			std::cout << "Error during the select function: " << WSAGetLastError() << '\n';

			return -10;
		}

		//loop trhought all ready sockets
		for (u_int i = 0; i < ready_fd; i++) {

			if (_temp_set.fd_array[i] == _ListenSocket) { //new connection request

				//check that the active clients are less than the allowed max
				if (_activeClient < _MaxClient) {
					//Client socket that gets created when the connectio is ready.
					SOCKET ClientSocket = accept(_ListenSocket, NULL, NULL);
					LogFiles(ClientSocket);
					_clientInfoMap[ClientSocket].hostName = _hostname;

					//error checking the accept function
					if (ClientSocket == INVALID_SOCKET) {
						std::cout << "Error happening in the accept function: " << WSAGetLastError() << '\n';
						return -10;
					}

					FD_SET(ClientSocket, &_master_set);//adding to master set
					++_activeClient; //increments active clients
					std::cout << "Clients connected to Server: " << _activeClient << '\n';
					
					StartLogging();

					//reset the buffer to 0
					memset(_SenBuff, 0, sizeof(_SenBuff));
					strcpy(_SenBuff, "Welcome To The Server \nFor Help and list of command, use ~help command ");

					//error check the message was send correctly
					if (SendHelper(ClientSocket) == 0) {
						std::cout << "Welcome message was sent to client \n";

					}
					else {
						std::cout << "Error while sending Welcome message \n";
					}

				}
				else { //Server is at full capacity
					std::cout << "Maximun clients In Server. Last connection rejected\n";
					SOCKET temp = accept(_ListenSocket, NULL, NULL);
					//reset buffer
					memset(_SenBuff, 0, sizeof(_SenBuff));
					strcpy(_SenBuff, "Server is Full Try Later");

					//error check that max cap message was send.
					int result = SendHelper(temp);
					if ((result == SOCKET_ERROR) || (result == 0)) {
						std::cout << "Max Capacity message was send\n";
					}
					else {
						std::cout << "Error happaned while sending Max Cap to Client\n";
					}
					shutdown(temp, SD_BOTH);
					closesocket(temp);
				}

			}
			else {//exit client socket

				if (FD_ISSET(_temp_set.fd_array[i], &_temp_set)) { //check that socket send any information.
					int result = ReadHelper(_temp_set.fd_array[i]); //if user disconnect it returns -1 else 0
					if (result == 0) {
						std::cout << "Message recieve: " << _RecvBuff << '\n'; 
						CommandFunction(_temp_set.fd_array[i]);
						
						//this will update the command logs to show the username the client picked after the client is logged in into the server
						auto it = _UsernameList.find(_temp_set.fd_array[i]);
						if (it != _UsernameList.end()) {
							_clientInfoMap[_temp_set.fd_array[i]].userName = it->second;
						}

						//ensure client is connected before it can send msg to all clients
						if (_clientLoginStatus[_temp_set.fd_array[i]]) {

							//message relay to all connected clients.
							for (u_int j = 0; j < masterSetCount; j++) {
								SOCKET targetSocket = _master_set.fd_array[j];
								if (targetSocket != _temp_set.fd_array[i] && _clientLoginStatus[targetSocket]) {
									//CHECK THAT WORDS DON'T START WITH~ SO YOU DONT SEND THE COMMANDS
									memset(_SenBuff, 0, sizeof(_SenBuff));
									strcpy(_SenBuff, _RecvBuff);
									if ((_SenBuff[0] != '~')) {
							
										SendHelper(targetSocket);

									}
									
								}
							}

						}
						else {
							if (_userDataBase.empty()) {
								std::cout << "Client is not logged in and cannot send messages to other clients.\n";
								memset(_SenBuff, 0, sizeof(_SenBuff));
								strcpy(_SenBuff, "PLEASE REGISTER USING ~register AND LOGIN");
								SendHelper(_temp_set.fd_array[i]);
							}
							else {
								std::cout << "Client is not logged in and cannot send messages to other clients.\n";
								memset(_SenBuff, 0, sizeof(_SenBuff));
								strcpy(_SenBuff, "PLEASE LOGIN");
								SendHelper(_temp_set.fd_array[i]);
							}
							
						}

						//create logs of public messages only but user needs to be registered and logged in first.
						if (_clientLogStatus[_temp_set.fd_array[i]]) {
							
							if((_SenBuff[0] != '~') && (_RecvBuff[0] != '~')) {

								for (const auto& pair : _UsernameList) {
									if (pair.first == _temp_set.fd_array[i]) {
										LogPublicMessage(pair.second, _SenBuff);
										break;
									}
								}
								 
							} //this make sure dms are not being saved into the logs
						}
						else {
							if ((_SenBuff[0] != '~') && (_RecvBuff[0] != '~')) {
								for (const auto& pair : _UsernameList) {
									if (pair.first == _temp_set.fd_array[i]) {
										LogPublicMessage(pair.second, _RecvBuff);
										break;
									}
								}
							} //this make sure dms are not being saved into the logs
						}

					}
					else {
						if (!_clientLoginStatus.empty()) {

							ProcessLogout(_temp_set.fd_array[i]);
							shutdown(_temp_set.fd_array[i], SD_BOTH);
							closesocket(_temp_set.fd_array[i]);
						}
						
					}
					
					
					
					
				}
				
			}

			
		}


	 }
	return 0;
}

//send helper function work correctly.
int Server::SendHelper(SOCKET client)
{
	const char* bufferToSend = _SenBuff;
	uint8_t size = strlen(_SenBuff) + 1; //buffer size plus '\0'
	
	int result = tcp_send_whole(client, (char*)&size, 1);
	if ((result == SOCKET_ERROR) || (result == 0)) {
		std::cout << "\n\nError happaned when using the tcp_send_whole: " << WSAGetLastError() << "\n";
		return 1; // it does not matter what I return as long is not 0
	}

	result = tcp_send_whole(client, bufferToSend, size);
	if ((result == SOCKET_ERROR) || (result == 0)) {
		std::cout << "\n\nError happaned when using the tcp_send_whole second call: " << WSAGetLastError() << "\n";
		return 1; // it does not matter what I return as long is not 0
		
	}

	

	return 0;
}

//ReadHelper save the recieved info into the _RecvBuff variable to be use in class
int Server::ReadHelper(SOCKET client)
{
	uint8_t size = 0;

	int result = tcp_recv_whole(client, (char*)&size, 1);
	//this is giving an error.
	if ((result == SOCKET_ERROR) || (result <= 0)) {
		std::cout << "Client disconnected\n";
		
		//SendHelper(client); NOTE TO SELF THIS MIGHT NOT WORK I'LL ASK ABOUT THIS.

		//clearing the fd_master
		FD_CLR(client, &_master_set);
		closesocket(client);
		--_activeClient;

		if (_activeClient < 0) { _activeClient = 0; }//check that _activeclient is not a huge number;
		std::cout << "Total Clients: " << _activeClient << '\n';
		return 1;
		
	}

	

	char* buffer = new char[size];
	result = tcp_recv_whole(client, (char*)buffer, size);
	if ((result == SOCKET_ERROR) || (result == 0)) {
		std::cout << "Error in the second call of recv helper function: " << WSAGetLastError() << '\n';
		delete[] buffer;
		return 1;
	}

	if (size <= sizeof(_RecvBuff)) {
		memcpy(_RecvBuff, buffer, size);
	}
	else {
		// Handle case where received data is larger than _RecvBuff
		memcpy(_RecvBuff, buffer, sizeof(_RecvBuff) - 1);
		_RecvBuff[sizeof(_RecvBuff) - 1] = '\0'; // Ensure null-termination
	}


	delete[] buffer;
	return 0;
}

//helper function given to me during the first coding lab. do not touch it.
int Server::tcp_send_whole(SOCKET s, const char* buffer, uint16_t len)
{
	int result;
	int bytesSent = 0;

	while (bytesSent < len) {
		result = send(s, (const char*)buffer + bytesSent, len - bytesSent, 0);
		if (result <= 0)
			return result;
		bytesSent += result;
	}

	return bytesSent;
}

// helper function given to me during firs coding lab. recieving function.
int Server::tcp_recv_whole(SOCKET s, char* buf, int len) {

	int total = 0;

	do
	{
		int ret = recv(s, buf + total, len - total, 0);
		if (ret < 1)
			return ret;
		else
			total += ret;

	} while (total < len);

	return total;
}

//function in charge of detecting and handling commands.
void Server::CommandFunction(SOCKET client)
{
	std::string clientInfo;
	std::string displayCmd;

	// Get client information (hostname and socket) if available
	auto it = _clientInfoMap.find(client);
	if (it != _clientInfoMap.end()) {
		clientInfo = it->second.hostName + ":" + std::to_string(client);
	}
	else {
		clientInfo = "Unknown:" + std::to_string(client);
	}

	if ((_RecvBuff[0] == '~')) {

		std::string cmd(_RecvBuff + 1);
		size_t spacePosCmd = cmd.find(' ');
		if (spacePosCmd != std::string::npos) {
			std::string targetUser = cmd.substr(0, spacePosCmd);
			displayCmd = '~'+targetUser;
			
		}

		if (spacePosCmd > 256) {
			displayCmd = '~' + cmd;
		}

		std::cout << "Command Recieved: " << displayCmd << '\n';
		_command.clear();

		//make it capitalized proof
		for (char ch : cmd) {
			_command += tolower(ch);
		}

		//log the commands no matter if user is online or not
		LogCommand(clientInfo, displayCmd);

		// Parse command and arguments
		size_t spacePos = _command.find(' ');
		std::string baseCommand = (spacePos != std::string::npos) ? _command.substr(0, spacePos) : _command;
		std::string arguments = (spacePos != std::string::npos) ? _command.substr(spacePos + 1) : "";

		if (baseCommand == "help") {
			memset(_SenBuff, 0, sizeof(_SenBuff));
			strcpy(_SenBuff, "Usable commands:\n~login: Connect to server using username and password"
                "\n~register: Client registration with username and password\n~getlist: Display list of active Users"
				"\n~logout: Disconnect client\n~send: Send direct message to user (~user username) msg");
			SendHelper(client);
		}
		else if (baseCommand == "register") {
			
			ProcessRegistration(client, arguments);
			
		}
		else if (baseCommand == "login") {
			
			if (ProcessLogin(client, arguments)) {
				
				std::cout << "client is logged in!" << '\n';
				_clientLoginStatus[client] = true;

			}

			
			
		}

		else if (baseCommand == "logout") {
			//check that client is online first
			if (_clientLoginStatus[client]) {
				ProcessLogout(client);
				HandleClientDisconnection(client);
			}
		}
		else if (baseCommand == "getlist") {
			if (_UsernameList.empty()) { return; }
			else {
				std::string listUsername = "Online Clients: \n";
				//append the list of username online into a string
				for (auto it = _UsernameList.begin(); it != _UsernameList.end(); it++) {
					listUsername += it->second + '\n';
				}
				// Ensure the buffer is large enough
				if (listUsername.size() >= sizeof(_SenBuff)) {
					std::cerr << "Error: List of usernames is too large for the buffer.\n";
					// Optionally, you can handle this by truncating or sending in parts
					listUsername = listUsername.substr(0, sizeof(_SenBuff) - 1); // Truncate the string to fit the buffer
				}

				// Clear the buffer
				memset(_SenBuff, 0, sizeof(_SenBuff));

				// Copy the string into the buffer
				strncpy(_SenBuff, listUsername.c_str(), sizeof(_SenBuff) - 1);

				//// Ensure null termination
				//_SenBuff[sizeof(_SenBuff) - 1] = '\0';

				// Send the buffer
				SendHelper(client);
				std::cout << listUsername;

			}
			
		}
		else if (_command.find("send ") == 0) { //THIS MIGHT NOT WORK 
			// Extract the rest of the command after "send "
			
			std::string remainingCommand = _command.substr(5);
			ProcessDMs(client, remainingCommand);
			memset(_SenBuff, 0, sizeof(_SenBuff));
		}
		else if (_command == "getlog") {
			memset(_SenBuff, 0, sizeof(_SenBuff));
			strcpy(_SenBuff, "-------BEGGINING OF LOG------");
			SendHelper(client);
			GetLog(client);
			memset(_SenBuff, 0, sizeof(_SenBuff));
			strcpy(_SenBuff, "-------END OF LOG------");
			SendHelper(client);
		}
		else {
			memset(_SenBuff, 0, sizeof(_SenBuff));
			strcpy(_SenBuff, "Unknown command.");
			SendHelper(client);
		}

		
	}
	

	
}

//append the strings saves it into the UserDatabse
bool Server::Tokenizer(const std::string regis)
{
	std::string UserName, UserPassWord;
	size_t delimiter = regis.find(' ');
	if (delimiter != std::string::npos) {
		UserName = regis.substr(0, delimiter);
		UserPassWord = regis.substr(delimiter + 1);
		
		//_userDataBase.insert(UserName, UserPassWord);
		_userDataBase[UserName] = UserPassWord;
				
		
		return true;
	}
	else {
		std::cout << "Error occurred parsing username and password.\n";
		return false;
	}
}

//validate the password and username
bool Server::ProcessLogin(SOCKET client, const std::string& arguments) {
	std::string username, password;
	size_t spacePos = arguments.find(' ');

	if (spacePos != std::string::npos) {
		username = arguments.substr(0, spacePos);
		password = arguments.substr(spacePos + 1);

		std::string name, pass;
		for (int i = 0; i < _master_set.fd_count; i++) {
			if (client == _master_set.fd_array[i]) {
				if (_userDataBase.find(username) != _userDataBase.end()) {
					name = username;
					pass = _userDataBase[username];
				}
			}
		}

		if ((name == username) && (pass == password)) {
			_clientLoginStatus[client] = true;
			_UsernameList[client] = username;
			memset(_SenBuff, 0, sizeof(_SenBuff));
			strcpy(_SenBuff, "You're Logged into the server!");
			SendHelper(client);
			return true;
		}
	}

	memset(_SenBuff, 0, sizeof(_SenBuff));
	strcpy(_SenBuff, "Login Failed. Check Username and Password match.");
	SendHelper(client);

	return false;
}

//print the server machine ip addresses.
void Server::PrintLocalIPAddresses() {
	char hostname[NI_MAXHOST];
	if (gethostname(hostname, NI_MAXHOST) != 0) {
		std::cerr << "Error getting hostname: " << WSAGetLastError() << std::endl;
		return;
	}

	struct addrinfo hints, * result, * ptr;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;  // Allow both IPv4 and IPv6
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	int res = getaddrinfo(hostname, NULL, &hints, &result);
	if (res != 0) {
		std::cerr << "getaddrinfo failed: " << gai_strerror(res) << std::endl;
		return;
	}

	std::cout << "IP addresses for " << hostname << ":" << std::endl;

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		void* addr;
		std::string ipver;

		// Get the pointer to the address itself,
		// different fields in IPv4 and IPv6:
		if (ptr->ai_family == AF_INET) {  // IPv4
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)ptr->ai_addr;
			addr = &(ipv4->sin_addr);
			ipver = "IPv4";
		}
		else if (ptr->ai_family == AF_INET6) {  // IPv6
			struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)ptr->ai_addr;
			addr = &(ipv6->sin6_addr);
			ipver = "IPv6";
		}
		else {
			continue;
		}

		// Convert the IP to a string and print it:
		char ipstr[INET6_ADDRSTRLEN];
		inet_ntop(ptr->ai_family, addr, ipstr, sizeof(ipstr));
		std::cout << "  " << ipver << ": " << ipstr << std::endl;
	}

	freeaddrinfo(result);
}

//oOLD LOG FILE FUNCTION
//save all comversations of the client into a file.

void Server::LogFiles(SOCKET client) {
	// Get the client's IP address
	sockaddr_in clientAddr;
	int addrLen = sizeof(clientAddr);
	getpeername(client, (sockaddr*)&clientAddr, &addrLen);

	char clientIP[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP));

	// Get the current time
	time_t now = time(0);
	tm* ltm = localtime(&now);

	// Format the time as YYYY-MM-DD HH:MM:SS
	std::ostringstream oss;
	oss << 1900 + ltm->tm_year << "-"
		<< 1 + ltm->tm_mon << "-"
		<< ltm->tm_mday << " "
		<< 1 + ltm->tm_hour << ":"
		<< 1 + ltm->tm_min << ":"
		<< 1 + ltm->tm_sec;

	std::string currentTime = oss.str();

	// Get the computer or network name
	gethostname(_hostname, 256);

	// Log to a file
	std::ofstream logFile("server_log.txt", std::ios_base::app); // Open log file in append mode
	if (logFile.is_open()) {
		logFile << "Client connected: " << clientIP << " at " << currentTime << " from " << _hostname << "\n"
			 << '\n';
		logFile.close();
	}
	else {
		std::cerr << "Unable to open log file" << std::endl;
	}
}

//proccess registration for the client
void Server::ProcessRegistration(SOCKET client, const std::string& arguments) {
	std::string username, password;
	size_t spacePos = arguments.find(' ');

	if (spacePos != std::string::npos) {
		username = arguments.substr(0, spacePos);
		password = arguments.substr(spacePos + 1);

		if (_userDataBase.find(username) != _userDataBase.end()) {
			memset(_SenBuff, 0, sizeof(_SenBuff));
			strcpy(_SenBuff, "Username already taken. Please choose another one.");
			SendHelper(client);
			return;
		}

		_userDataBase[username] = password;
		memset(_SenBuff, 0, sizeof(_SenBuff));
		strcpy(_SenBuff, "User Registration Successful");
		SendHelper(client);

		std::cout << "User Registered: " << username << std::endl;
	}
	else {
		memset(_SenBuff, 0, sizeof(_SenBuff));
		strcpy(_SenBuff, "Invalid format. Please enter the username and password separated by a space.");
		SendHelper(client);
	}
}

//start the process of opening the files
void Server::StartLogging() {
	if (!_publicMsgLogs.is_open()) {
		_publicMsgLogs.open("public_messages_log.txt", std::ios_base::app);
	}
	if (!_commandLogs.is_open()) {
		_commandLogs.open("commands_log.txt", std::ios_base::app);
	}
}

//handle direct messages from C to C
void Server::ProcessDMs(SOCKET client, const std::string& remainingCommand)
{
	// Find the first space to separate username and message
	size_t spacePos = remainingCommand.find(' ');
	if (spacePos != std::string::npos) {
		std::string targetUser = remainingCommand.substr(0, spacePos);
		std::string message = remainingCommand.substr(spacePos + 1);

		// Find the target client's socket
		SOCKET targetSocket = INVALID_SOCKET;
		for (const auto& pair : _UsernameList) {
			if (pair.second == targetUser) {
				targetSocket = pair.first;
				break;
			}
		}

		if (targetSocket != INVALID_SOCKET) {
			memset(_SenBuff, 0, sizeof(_SenBuff));
			strncpy(_SenBuff, message.c_str(), sizeof(_SenBuff) - 1);
			SendHelper(targetSocket);

			// Confirmation to the sender
			memset(_SenBuff, 0, sizeof(_SenBuff));
			snprintf(_SenBuff, sizeof(_SenBuff), "Message sent to %s", targetUser.c_str());
			SendHelper(client);
			//memset(_SenBuff, 0, sizeof(_SenBuff));
			//memset(_RecvBuff, 0, sizeof(_RecvBuff));
		}
		else {
			memset(_SenBuff, 0, sizeof(_SenBuff));
			strcpy(_SenBuff, "User not found.");
			SendHelper(client);
			//memset(_SenBuff, 0, sizeof(_SenBuff));
			//memset(_RecvBuff, 0, sizeof(_RecvBuff));
		}
	}
	else { //Showing the client how to use the command properly
		memset(_SenBuff, 0, sizeof(_SenBuff));
		strcpy(_SenBuff, "Usage: ~send <username> <message>");
		SendHelper(client);
	}

}

//log all public messages
void Server::LogPublicMessage(const std::string& client, const std::string& message) {
	if (_publicMsgLogs.is_open()) {
		_publicMsgLogs << client <<": "<< message << '\n';
		_publicMsgLogs.flush();
	}
}

void Server::GetLog(SOCKET client)
{
	std::string readFile;
	std::ifstream logFile("public_messages_log.txt");

	while (getline(logFile, readFile)) {
		
		// Clear the buffer
		memset(_SenBuff, 0, sizeof(_SenBuff));

		// Copy the string into the buffer
		strncpy(_SenBuff, readFile.c_str(), sizeof(_SenBuff) - 1);

		SendHelper(client);
	}

	logFile.close();
}

void Server::ProcessLogout(SOCKET client)
{
	_clientLoginStatus[client] = true; // make the client to go offline
	//_clientLogStatus[client] = false;
	_UsernameList.erase(client); //remove offline username from list;
	memset(_SenBuff, 0, sizeof(_SenBuff));
	strcpy(_SenBuff, "You're LogOut! XD ");
	SendHelper(client);


	
}

void Server::HandleClientDisconnection(SOCKET client)
{
	// Clear the client from the master set
	FD_CLR(client, &_master_set);

	// Shutdown and close the socket
	shutdown(client, SD_BOTH);
	closesocket(client);

	// Decrement the active client count
	--_activeClient;
	if (_activeClient < 0) { _activeClient = 0; }

	std::cout << "Total Clients: " << _activeClient << '\n';

}

//log all commands after logging is enable
void Server::LogCommand(const std::string& client, const std::string& command) {
	if (_commandLogs.is_open()) {
		_commandLogs << client << ": " << command << '\n';
		_commandLogs.flush();
	}
}










