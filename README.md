# CryptoChat: Implementing Secure Group Communication

## Description

Our final project implements a messaging protocol supporting three-person 
group chats, providing users with a platform where they can chat confidently, 
knowing that their conversations are protected from the server. This effort 
represents an important step towards enhancing digital privacy in an age where 
data security is increasingly precarious.

Full report: https://drive.google.com/file/d/15RrW8Ytpg3xrUlh7yFa7_Pvys0IMF0qq/view?usp=drive_link 
Presentation Link: https://drive.google.com/file/d/1DyFA7w3YgKkbBEUSkCqiOuASUupqXTrG/view?usp=drive_link 

## Installation

1. Clone the repository:
`git clone https://github.com/nhaseley/groupchat-auth-nhaseley-yanaw02.git`
Clone the project into your `devenv/home folder` in the CS1515 container. 
From here you can access the code from both your computer and from the Docker 
container. For instructions on downloading and accessing the CS1515 Docker 
container, please visit this [link](https://cs.brown.edu/courses/csci1515/spring-2024/misc/devenv.html).

2. Navigate to the build folder: `cd build`

3. Install dependencies:
Run `cmake ..`. This will generate a set of Makefiles building the whole project. 
From here, you can run `make` to generate a binary you can run, and you can 
run `make check` to run any tests you write in the test folder.

## Usage

To run the user binary, run `./auth_user <config file>`. We have provided user
config files for you to use, but feel free to experiment with more users. 
Afterwards, you can either choose to `login`, `register`, `connect`, 
or `listen`; the former two deal with other server binaries, the latter two
deal with other user binaries. They call the corresponding `Handle` functions in code. 

To run the server binary, run `./auth_server <port> <config file>`. We have 
provided server config files for you to use. Afterwards, the server will start 
listening for connections and handle them in separate threads.

TODO: ADJUST WITH COMMAND FOR RUNNING EACH USER

## Project Contributions

### Nya
- Implemented and debugged cryptographic key generation protocol on both User and Server side
    - `UserClient::HandleGCMessage`
    - `ServerClient::GetKeys`
    - `ServerClient::GenerateGCKey`
    - `UserClient::GenerateGCKey`
- Adjusted existing project to function for both user and admin roles
- Created new message structs and their corresponding `deserialize` and `serialize` methods
- Completed final project report and presentation
- Completed `README.md`

### Amy
- Implemented set up basic, unsafe communication between server and users without any crytographic encryption 
    - `ServerClient::HandleGCConnection`
    - `ServerClient::SendToAll`
    - `UserClient::DoMessageGC`
    - `UserClient::ReceiveGCThread`
    - `UserClient::SendGCThread`
- Assisted with key generation debugging
- Worked on final project report

# `Client.cxx` Overview

This file is part of a messaging system designed to facilitate communication between users via a server. Below is a breakdown of its key functionalities:

## Included Libraries

- `#include <cmath>`: Provides mathematical functions like pow().
- `#include <cstdlib>`: Standard library for general utilities.
- `#include <iomanip>`: Input/output manipulators for formatted output.
- `#include <iostream>`: Input/output stream objects for console I/O.
- `#include <stdexcept>`: Defines a set of standard exceptions.
- `#include <string>`: String handling functions and classes.
- `#include <sys/ioctl.h>`: System-specific I/O control operations.

## External Libraries

- `#include <boost/asio.hpp>`: Boost library for asynchronous I/O operations.
- `#include <boost/lexical_cast.hpp>`: Boost library for converting data types.

## Constructor (UserClient)

- Initializes the client with network and cryptography drivers.
- Loads user configuration, including keys.

## `run()`

- Initiates the Read-Eval-Print Loop (REPL) for user interaction.
- Listens for commands such as login, register, listen, connect, and gc (group chat).
- Pre-existing function from Auth Project

## `HandleGCMessage()`

- Processes messages for group chat.
- Parses input, connects to specified address and port, and executes group chat message exchange.

## `DoMessageGC()`

- Initiates group chat message exchange.
- Includes key generation, encryption, and message sending and receiving.

## `ReceiveGCThread()`

- Continuously listens for incoming messages in a separate thread for group chat.
- Decrypts and verifies messages, and prints them to the command line.

## `SendGCThread()`

- Reads messages from standard input.
- Encrypts and tags messages, and sends them to other users in group chat.

## `GenerateGCKey()`

- Implements group chat key generation process.
- Includes Diffie-Hellman key exchange and message encryption.

## `HandleServerKeyExchange()`

- Manages Diffie-Hellman key exchange with the server.
- Generates and exchanges public keys.
- Pre-existing function from Auth Project

## `HandleUserKeyExchange()`

- Manages Diffie-Hellman key exchange with another user.
- Generates and exchanges public keys.
- Pre-existing function from Auth Project

## `HandleLoginOrRegister()`

- Handles user login or registration.
- Connects to the server, exchanges keys, and sends user credentials.
- Pre-existing function from Auth Project

## `DoLoginOrRegister()`

- Implements login or registration process.
- Exchanges keys, sends user credentials, and receives server responses.
- Pre-existing function from Auth Project

Overall, this client code offers a comprehensive set of functionalities for secure messaging, including encryption, key exchange, user authentication, and group chat capabilities.

# `Server.cxx` Overview

This file is a part of a server-side application designed to handle client connections, user registration, and authentication. Below is a breakdown of its main components and functionalities:

## Included Libraries

- `#include <cmath>`: Provides mathematical functions like pow().
- `#include <cstdlib>`: Standard library for general utilities.
- `#include <iomanip>`: Input/output manipulators for formatted output.
- `#include <iostream>`: Input/output stream objects for console I/O.
- `#include <stdexcept>`: Defines a set of standard exceptions.
- `#include <string>`: String handling functions and classes.
- `#include <sys/ioctl.h>`: System-specific I/O control operations.

## External Libraries

- `#include <boost/asio.hpp>`: Boost library for asynchronous I/O operations.
- `#include <boost/lexical_cast.hpp>`: Boost library for converting data types.

## Constructor (UserClient)

- Initializes the client with CLI and database drivers.
- Loads server keys.

## `run()`

- Starts a listener thread.
- Initiates a Read-Eval-Print Loop (REPL) for handling client connections.
- Pre-existing function from Auth Project

## `Reset()`

- Resets the database.
- Pre-existing function from Auth Project

## `Users()`

- Prints all usernames stored in the database.
- Pre-existing function from Auth Project

## `ListenForConnections()`

- Listens for incoming client connections in a separate thread.
- Pre-existing function from Auth Project

## `HandleGCConnection()`

- Handles group chat connections, including key exchange and message transmission.

## `SendToAll()`

- Sends messages to all clients except the sender.

## `GetKeys()`

- Receives public keys from clients participating in group chat.

## `GenerateGCKey()`

- Generates group chat keys and distributes them to clients.

## `HandleConnection()`

- Handles individual client connections, including user authentication and registration.
- Pre-existing function from Auth Project

## `HandleKeyExchange()`

- Implements Diffie-Hellman key exchange protocol.
- Pre-existing function from Auth Project

## `HandleLogin()`

- Handles user login requests, including password verification and certificate generation.
- Pre-existing function from Auth Project

## `HandleRegister()`

- Handles user registration requests, including password hashing and certificate generation.
- Pre-existing function from Auth Project

## Overall Functionality

- The `ServerClient` class serves as the main server application.
- It handles both individual client connections and group chat sessions.
- Implements secure authentication and registration mechanisms using encryption and digital signatures.
- The server maintains a database of registered users and their credentials.

This code snippet provides a comprehensive server-side implementation for handling client connections, user authentication, and registration in a secure manner.

## Acknowledgments

Thank you so much to our wonderful CS1515 professor Peihan Miao and final 
project teaching assistant Nishchay Parashar (Github: nishchayp) for their support on 
this project as well as throughout this semester!

## Disclaimer

This project was a final project built off the foundations from 
Brown University's CS1515 Applied Cryptography Auth Project.

Feel free to play around and watch the magic of secure communication unfold!