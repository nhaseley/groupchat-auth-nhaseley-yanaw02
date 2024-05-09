# Project Name

Group Chat

## Description

Our final project aims to create a secure server-client authentication system 
that supports a 3-person group chat. Our goal is to provide users with a 
platform where they can chat confidently, knowing that their conversations are 
protected from unwanted access and hiding the group structure from the server. 
This effort represents an important step towards enhancing digital privacy in 
an age where data security is increasingly precarious.

TODO: add final report link

## Installation

1. Clone the repository:
`git clone https://github.com/nhaseley/groupchat-auth-nhaseley-yanaw02.git`
Clone the project into your `devenv/home folder` in the CS1515 container. 
From here you can access the code from both your computer and from the Docker 
container. For instructions on downloading and accessing the CS1515 Docker 
container, please visit this [link](https://cs.brown.edu/courses/csci1515/spring-2024/misc/devenv.html).

2. Navigate to the build folder:

`cd build`

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

## Project Contributions

Nya
- Implemented and debugged cryptographic key generation protocol on both User and Server side
    - `UserClient::HandleGCMessage`
    - `ServerClient::GetKeys`
    - `ServerClient::GenerateGCKey`
    - `UserClient::GenerateGCKey`
- Adjusted existing project to function for both user and admin roles
- Created new message structs and their corresponding `deserialize` and `serialize` methods
- Worked on final project report and presentation
- Completed `README.md`

Amy
- Implemented set up basic, unsafe communication between server and users without any crytographic encryption 
    - `ServerClient::HandleGCConnection`
    - `ServerClient::SendToAll`
    - `UserClient::DoMessageGC`
    - `UserClient::ReceiveGCThread`
    - `UserClient::SendGCThread`
- Assisted with key generation debugging
- Worked on final project report and presentation

## Acknowledgments

Thank you so much to our wonderful CS1515 professor Peihan Miao and final 
project teaching assistant Nishchay Parashar (nishchayp) for their support on 
this project as well as throughout this semester!

## Disclaimer

This project was a final project built off the foundations from 
Brown University's CS1515 Applied Cryptography Auth Project.

Feel free to customize the sections and content based on your project's specifics!