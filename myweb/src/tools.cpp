//-----------------------------------------------------------------------------
 // tools.cpp
//  Implementation of Simple Web Request Tool cpp file
//  Name: David Shonack
//  CruzID: dshonack
//-----------------------------------------------------------------------------

#include <cassert>
#include <iostream>
#include <sys/socket.h>
#include <string>
#include "tools.h"
#include <sys/un.h>
#include <arpa/inet.h> 
#include <unistd.h>  
#include <fstream>
#define BUFFER_SIZE 1024
using namespace std; 
/*
struct sockaddr_in {
    sa_family_t    sin_family;   // Address family (e.g., AF_INET for IPv4)
    in_port_t      sin_port;     // Port number (16-bit, network byte order)
    struct in_addr sin_addr;     // IPv4 address (32-bit, network byte order)
    char           sin_zero[8];  // Padding to make structure size match sockaddr
};


struct in_addr {
    uint32_t s_addr; // 32-bit IPv4 address (network byte order)
};
*/ 


// Constructor && Destructor --------------------------------------------------

WebReq::WebReq(const std::string &url, const std::string &query, const std::string &resource_path, bool header = 0, const std::string &port = "80"){
	socket_fd 						= socket(AF_INET, SOCK_STREAM , 0);
	assert( socket_fd != -1 ); 	// Assertion checks for a socket creation failure
	this->url 						= url; 
	this->query 					= query;
	this->header 					= header; 
	server_address.sin_family 		= AF_INET;
	server_address.sin_port 		= htons(80);
	this->resource_path 			= resource_path;
	assert( head_get_request() != -1 ); // Assertion checks for a failed request
	assert( head_get_recieve() != -1 ); // Assertion checks for a failed recieve
}


// 
int WebReq::head_get_request(){

	std::string request;

	if (inet_pton(AF_INET, query.c_str(), &server_address.sin_addr) <= 0) 
	{
		cerr << "Invalid Address not supported" << endl;
		return -1; 
	}
	
	if (connect(socket_fd, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) {
		cerr << "ERROR: Failed to connect to server!" << endl; 
		return -1; 
	}

	std::string host_header = "Host: " + url;
	if (resource_path == "") {
		// If resource_path is empty, make the request without a resource path
		request = (header == 0)
			? "GET / HTTP/1.1\r\n" + host_header + "\r\nConnection: close\r\n\r\n"
			: "HEAD / HTTP/1.1\r\n" + host_header + "\r\nConnection: close\r\n\r\n";
	} else {
		// If resource_path is not empty, append it to the request
		request = (header == 0)
			? "GET " + resource_path + " HTTP/1.1\r\n" + host_header + "\r\nConnection: close\r\n\r\n"
			: "HEAD " + resource_path + " HTTP/1.1\r\n" + host_header + "\r\nConnection: close\r\n\r\n";
	}

	if ( send(socket_fd, request.c_str(), request.length(), 0) == -1 ) {
		cerr << "ERROR: Failed to send request!" << endl; 
		return -1; 
	}
	return 0;
}

int WebReq::head_get_recieve(){
	char buffer						[BUFFER_SIZE];
	ssize_t 						bytes_received;
	size_t 							start = 0;
	size_t 							header_end = -1;
	if (header == 1) {
		while((bytes_received = recv(socket_fd, buffer, BUFFER_SIZE - 1, 0)) > 0){
			buffer[bytes_received] = '\0';
        	cout << buffer;  // Print the buffer if "Connection: close" is not found
		}
	}

	else{
		ofstream file("output.dat", std::ios::app);
		while((bytes_received = recv(socket_fd, buffer, BUFFER_SIZE - 1, 0)) > 0){
			buffer[bytes_received] = '\0';
			header_end = std::string(buffer).find("\r\n\r\n");
			if( header_end != std::string::npos ){
				start = 1;
				file << buffer + header_end + 4;
				// cout << buffer + header_end + 4;
			}
			else if (start == 1){
				file << buffer;
				// cout << buffer;
		}
		}
		file.close();
	}
		return 0;
}

WebReq::~WebReq(){
	 close(socket_fd);

}


