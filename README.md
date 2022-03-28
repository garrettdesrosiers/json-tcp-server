# json-tcp-server

A simple HTTP server fulfilling basic requests made for a Networks assignment. This project uses select() and event driven programming to handle multiple client requests simultaneously. Supports both iPv4 and iPv6 connections. A makefile is included.

To connect to the server, simply run the executeable from the command line (the default IP address that the server is bound to is the loopback IP address 127.0.0.1).
An iPv4 address can be specified as the first and only command line argument given in dotted-quad notation. 
Alternatively an iPv6 address can be specified in hexadecimal colon format as per standard. 
