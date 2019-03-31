// socket_example.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <winsock2.h>

#pragma comment(lib,"ws2_32.lib")

int main(void)
{
	WSADATA WsaDat;
	if (WSAStartup(MAKEWORD(2, 2), &WsaDat) != 0)
	{
		std::cout << "Winsock error - Winsock initialization failed\r\n";
		WSACleanup();
		system("PAUSE");
		return 0;
	}

	// Create our socket

	SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (Socket == INVALID_SOCKET)
	{
		printf("Winsock error - Socket creation Failed!\r\n");
		WSACleanup();
		system("PAUSE");
		return 0;
	}

	// Resolve IP address for hostname
	struct hostent *host;
	if ((host = gethostbyname("127.0.0.1")) == NULL)
	{
		printf("Failed to resolve hostname.\r\n");
		WSACleanup();
		system("PAUSE");
		return 0;
	}

	// Setup our socket address structure
	SOCKADDR_IN SockAddr;
	SockAddr.sin_port = htons(80);
	SockAddr.sin_family = AF_INET;
	SockAddr.sin_addr.s_addr = *((unsigned long*)host->h_addr);

	// Attempt to connect to server
	if (connect(Socket, (SOCKADDR*)(&SockAddr), sizeof(SockAddr)) != 0)
	{
		printf("Failed to establish connection with server\r\n");
		WSACleanup();
		system("PAUSE");
		return 0;
	}

	// Display message from server
	char buffer[1000];
	memset(buffer, 0, 999);
	int inDataLength = recv(Socket, buffer, 1000, 0);
	printf("%s\n", buffer);
	int nError = WSAGetLastError();
	if (nError != WSAEWOULDBLOCK && nError != 0)
	{
		printf("Winsock error code: %d\r\n", GetLastError());
		shutdown(Socket, SD_SEND);
		closesocket(Socket);
	}
	Sleep(1000);

	WSACleanup();
	system("PAUSE");
	return 0;
}