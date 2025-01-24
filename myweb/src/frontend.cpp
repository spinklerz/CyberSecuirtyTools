#include <iostream>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <regex>
#include "tools.h"
using namespace std;

int main(int argc, char** argv ) {

	regex 		pattern1(R"([A-Za-z.]*)");  	// extract url possibly resource path
	regex 		pattern2(R"(^[0-9.]*)"); 		// extract IP address possbily resource path
	regex		pattern3(R"(:[0-9]*)"); 		// Match port number
	string 		url;
	string		ip; 
	string		resource_path = "";
	string		port;
	string		input_str;
	smatch 		match;
	bool 		header = 0;
	// Check Arguements
	if( !( ( argc >= 3 ) && ( argc <= 4 ) ) ){ 
		cerr << "ERROR: Incorrect number of arguements!\n"
		<< "Examples:\n"
		<< "	./myweb www.example.com 93.184.216.34:80/index.html\n"
		<< "	./myweb www.example.com 93.184.216.34/index.html -h\n";
		return ( EXIT_FAILURE );
	}
	if (argc == 4) {
		if ( (strcmp(argv[3], "-h") == 0) ) {
			header = 1;
		}
		else {
			cerr << "ERROR: Invalid flag!\n"
			<< "Examples:\n"
			<< "	./myweb www.example.com 93.184.216.34:80/index.html\n"
			<< "	./myweb www.example.com 93.184.216.34/index.html -h\n";
			return ( EXIT_FAILURE );}
	}
	input_str = argv[1];
	
	// Check for this case ./myweb www.example.com/index.html 192.168.0.1 to extract url and resource_path
	if ( regex_search( input_str, match, pattern1 ) ) {
		url = match[0];
		resource_path = input_str.substr( match.position() + match.length() );
	}
	
	input_str = argv[2];
	
	// Checking for ./myweb www.example.com 93.184.216.34:80/index.html case to extract ip and resource_path
	if ( regex_search( input_str, match, pattern2 ) ){
		ip = match[0];
		if ( regex_search( input_str, match, pattern3 ) ){
			port = match[0].str().substr(1); 
		}
		resource_path = input_str.substr( match.position() + match.length() );

		size_t pos = input_str.find('/');
		if (pos != std::string::npos) {
			resource_path = input_str.substr(pos);
		}
	}
    

	// Convert to lowercase ****************************************************
	for( int i = 0; i < (int)url.length(); i++ ){
		url[i] = tolower(url[i]);
	}

	for( int i = 0; i < (int)resource_path.length(); i++ ){
		resource_path[i] = tolower(resource_path[i]);
	}
	// ****************************************************************************
	/*
	cout << "URL: " << url << endl; 
	cout << "IP: " << ip << endl; 
	cout << "Resource Path: " << resource_path << endl;
	cout << "Port: " << port << endl;
	*/
    WebReq A(url, ip, resource_path, header, port);
    return ( EXIT_SUCCESS );
}
