//-----------------------------------------------------------------------------
 // tools.h
//  Implementation of Simple Web Request Tool Header file
//  Name: David Shonack
//  CruzID: dshonack
//-----------------------------------------------------------------------------


// Headers --------------------------------------------------------------------

#ifndef TOOLS_H
#define TOOLS_H

#include<iostream>
#include<string>
#include <sys/un.h>
#include <sys/socket.h>
#include <netinet/in.h> 


// Class ----------------------------------------------------------------------

class WebReq{

	private: 
	// Variables ----------------------------------------------------------
		struct sockaddr_in server_address;
		int socket_fd; 
		std::string url; 
		std::string query;
		std::string port;
		std::string resource_path;
		bool header;
		
	public:
	// Constructor Destructor ---------------------------------------------
	
		WebReq(const std::string &url, const std::string &query, const std::string &resource_path, bool header, const std::string &port);
		int head_get_request();
		int head_get_recieve();
		~WebReq();
	
	// Core variables -----------------------------------------------------
	
		struct sockaddr_in address;

};


#endif // TOOLS_H
