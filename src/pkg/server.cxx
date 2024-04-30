#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/server.hpp"
#include "../../include/pkg/user.hpp"

/**
 * Constructor
 */
ServerClient::ServerClient(ServerConfig server_config) {
  // Initialize cli driver.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->cli_driver->init();

  // Initialize database driver.
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(server_config.server_db_path);
  this->db_driver->init_tables();

  // Load server keys.
  try {
    LoadRSAPrivateKey(server_config.server_signing_key_path,
                      this->RSA_signing_key);
    LoadRSAPublicKey(server_config.server_verification_key_path,
                     this->RSA_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find server keys, generating them instead.");
    CryptoDriver crypto_driver;
    auto keys = crypto_driver.RSA_generate_keys();
    this->RSA_signing_key = keys.first;
    this->RSA_verification_key = keys.second;
    SaveRSAPrivateKey(server_config.server_signing_key_path,
                      this->RSA_signing_key);
    SaveRSAPublicKey(server_config.server_verification_key_path,
                     this->RSA_verification_key);
  }
}

/**
 * Run the server on the given port. First initializes the CLI and database,
 * then starts listening for connections.
 */
void ServerClient::run(int port) {
  // Start listener thread
  std::thread listener_thread(&ServerClient::ListenForConnections, this, port);
  listener_thread.detach();

  // Start REPL
  REPLDriver<ServerClient> repl = REPLDriver<ServerClient>(this);
  repl.add_action("reset", "reset", &ServerClient::Reset);
  repl.add_action("users", "users", &ServerClient::Users);
  repl.run();
}

/**
 * Reset database
 *
 */
void ServerClient::Reset(std::string _) {
  this->cli_driver->print_info("Erasing users!");
  this->db_driver->reset_tables();
}

/**
 * Prints all usernames
 */
void ServerClient::Users(std::string _) {
  this->cli_driver->print_info("Printing users!");
  std::vector<std::string> usernames = this->db_driver->get_users();
  if (usernames.size() == 0) {
    this->cli_driver->print_info("No registered users!");
    return;
  }
  for (std::string username : usernames) {
    this->cli_driver->print_info(username);
  }
}

/**
 * @brief This is the logic for the listener thread
 */
void ServerClient::ListenForConnections(int port) {
  while (1) {
    // Create new network driver and crypto driver for this connection
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    network_driver->listen(port);
    std::thread connection_thread(&ServerClient::HandleConnection, this,
                                  network_driver, crypto_driver);
    connection_thread.detach();
  }
}

/**
 * Handle keygen and handle either logins or registrations. This function
 * should: 1) Handle key exchange with the user.
 * 2) Reads a UserToServer_IDPrompt_Message and determines whether the user is
 * attempting to login or register and calls the corresponding function.
 * 3) Disconnect the network_driver, then return true.
 */
bool ServerClient::HandleConnection(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver) {
  try {
    // TODO: implement me!
    // Step 1
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys = HandleKeyExchange(network_driver, crypto_driver);
    // Step 2
    UserToServer_IDPrompt_Message msg;
    // Get fields in msg
    std::vector<unsigned char> data = network_driver->read();
    // msg.deserialize(data);

    auto dec_vrfy_data = crypto_driver->decrypt_and_verify(std::get<0>(keys), std::get<1>(keys), data);
    // hashSaltPwdMsg.deserialize(hashSaltPwdData);
    if (std::get<1>(dec_vrfy_data) == false){
      std::cout << "Server could not decrypt/verify IDPrompt_Message" << std::endl;
      network_driver->disconnect();
      throw std::runtime_error("Server could not decrypt/verify IDPrompt_Message");
    }
    msg.deserialize(std::get<0>(dec_vrfy_data));


    if (msg.new_user == true){
      std::cout << "Registering...." << std::endl;
      HandleRegister(network_driver, crypto_driver, msg.id, keys);
      std::cout << "Registered successfully!" << std::endl;

    } else { // user is logging in 
      std::cout << "Logging in...." << std::endl;
      HandleLogin(network_driver, crypto_driver, msg.id, keys);
      std::cout << "Logged in successfully!" << std::endl;
    }

    // Step 3
    network_driver->disconnect();
    return true;
  } catch (...) {
    this->cli_driver->print_warning("Connection threw an error");
    network_driver->disconnect();
    return false;
  }
}

/**
 * Diffie-Hellman key exchange. This function should:
 * 1) Receive the user's public value
 * 2) Generate and send a signed DH public value
 * 3) Generate a DH shared key and generate AES and HMAC keys.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
ServerClient::HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                                std::shared_ptr<CryptoDriver> crypto_driver) {
  // TODO: implement me!
  std::tuple<DH, SecByteBlock, SecByteBlock> initializedParams = crypto_driver->DH_initialize();
  DH DH_obj = std::get<0>(initializedParams);
  SecByteBlock DH_private_value = std::get<1>(initializedParams);
  SecByteBlock DH_public_value = std::get<2>(initializedParams);

  // Step 1
  UserToServer_DHPublicValue_Message userDHMsg;
  std::vector<unsigned char> data = network_driver->read();
  userDHMsg.deserialize(data);
  
  // Step 2
  ServerToUser_DHPublicValue_Message serverDHMsg;

  std::vector<unsigned char> message = concat_byteblocks(DH_public_value, userDHMsg.public_value);
  std::string signature = crypto_driver->RSA_sign(this->RSA_signing_key, message);

  serverDHMsg.server_public_value = DH_public_value;
  serverDHMsg.user_public_value = userDHMsg.public_value;
  serverDHMsg.server_signature = signature;
  std::vector<unsigned char> serverDHData;
  serverDHMsg.serialize(serverDHData);
  network_driver->send(serverDHData);

  // Step 3
  SecByteBlock shared_key = crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, userDHMsg.public_value);
  SecByteBlock AESKey = crypto_driver->AES_generate_key(shared_key);
  SecByteBlock HMACKey = crypto_driver->HMAC_generate_key(shared_key);

  return std::make_pair(AESKey, HMACKey);
}

/**
 * Log in the given user. This function should:
 * 1) Find the user in the database.
 * 2) Send the user's salt and receive a hash of the salted password.
 * 3) Try all possible peppers until one succeeds.
 * 4) Receive a 2FA response and verify it was generated in the last 60 seconds.
 * 5) Receive the user's verification key, and sign it to create a certificate.
 * @param id id of the user logging in
 * @param keys tuple of AES_key, HMAC_key corresponding to this session
 */
void ServerClient::HandleLogin(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  // TODO: implement me!
  // Step 1
  UserRow user = this->db_driver->find_user(id);
  if (user.user_id == ""){
    std::cout << "A user does not exist in the database with id: " << id << std::endl;
    network_driver->disconnect();
    throw std::runtime_error("A user does not exist in the database with id: " + id);
  }

  // Step 2
  ServerToUser_Salt_Message saltMsg;
  saltMsg.salt = user.password_salt;
  // std::vector<unsigned char> saltData;
  
  // saltMsg.serialize(saltData);
  std::vector<unsigned char> encrypt_tag_SaltData = crypto_driver->encrypt_and_tag(std::get<0>(keys), std::get<1>(keys), &saltMsg);

  // network_driver->send(saltData);
  network_driver->send(encrypt_tag_SaltData);

  UserToServer_HashedAndSaltedPassword_Message hashSaltPwdMsg;
  std::vector<unsigned char> hashSaltPwdData = network_driver->read();

  auto dec_vrfy_SaltPwd = crypto_driver->decrypt_and_verify(std::get<0>(keys), std::get<1>(keys), hashSaltPwdData);
  // hashSaltPwdMsg.deserialize(hashSaltPwdData);
  if (std::get<1>(dec_vrfy_SaltPwd) == false){
    std::cout << "Server could not decrypt/verify HashedAndSaltedPassword_Message." << std::endl;
    network_driver->disconnect();
    throw std::runtime_error("Server could not decrypt/verify HashedAndSaltedPassword_Message.");
  }
  hashSaltPwdMsg.deserialize(std::get<0>(dec_vrfy_SaltPwd));
  // Step 3
  bool found = false;
  for (int i = 0; i < std::pow(2, 8); ++i) {
    std::string pepper(1, (char)i);

    if (crypto_driver->hash(hashSaltPwdMsg.hspw + pepper) == user.password_hash){
      found = true;
      break;
    }
  }    

  if (!found){
    std::cout << "Server could not find a matching password in the database for h_i:" << hashSaltPwdMsg.hspw << std::endl;
    network_driver->disconnect();
    throw std::runtime_error("Could not find a matching password in the database for h_i: " + hashSaltPwdMsg.hspw);
  }

  // Step 4
  UserToServer_PRGValue_Message prgValMsg;
  std::vector<unsigned char> prgValData = network_driver->read();
  auto dec_vrfy_prgVal = crypto_driver->decrypt_and_verify(std::get<0>(keys), std::get<1>(keys), prgValData);

  if (std::get<1>(dec_vrfy_prgVal) == false){
    std::cout << "Server could not decrypt/verify PRGValue_Message." << std::endl;
    network_driver->disconnect();
    throw std::runtime_error("Server could not decrypt/verify PRGValue_Message.");
  }
  prgValMsg.deserialize(std::get<0>(dec_vrfy_prgVal));
  // prgValMsg.deserialize(prgValData);
  CryptoPP::SecByteBlock r = prgValMsg.value; // Q: verify r that it was generate in last 60 seconds?
  

  std::vector<unsigned char> seedData;
  // std::cout << "JUST DESERIALIZED" << std::endl;

  // std::cout << "SEED TO CHECK: " << user.prg_seed << std::endl;

  Integer currTime = crypto_driver->nowish();
  bool validR = false;
  for (int i = 0; i < 60; ++i) {
    if (prgValMsg.value == crypto_driver->prg(string_to_byteblock(user.prg_seed), integer_to_byteblock(currTime - i), PRG_SIZE)){
      // found time within the past 60 seconds
      validR = true;
      break;
    }
  }
  if (!validR){
    std::cout << "Server could not find valid certificate for: " << byteblock_to_string(prgValMsg.value) << std::endl;
    network_driver->disconnect();
    throw std::runtime_error("This ceritficate has expired.");
  }

  // Step 5
  UserToServer_VerificationKey_Message vrfkyMsg;
  std::vector<unsigned char> vrfkyData = network_driver->read();
  
  auto dec_vrfy_vfrky = crypto_driver->decrypt_and_verify(std::get<0>(keys), std::get<1>(keys), vrfkyData);

  if (std::get<1>(dec_vrfy_vfrky) == false){
    std::cout << "Server could not decrypt/verify VerificationKey_Message." << std::endl;
    network_driver->disconnect();
    throw std::runtime_error("Server could not decrypt/verify VerificationKey_Message.");
  }

  // vrfkyMsg.deserialize(vrfkyData);
  vrfkyMsg.deserialize(std::get<0>(dec_vrfy_vfrky));
  CryptoPP::RSA::PublicKey vrfkyKey = vrfkyMsg.verification_key;

  std::vector<unsigned char> message = concat_string_and_rsakey(id, vrfkyKey);
  std::string signature = crypto_driver->RSA_sign(this->RSA_signing_key, message);

  Certificate_Message certMsg;
  certMsg.id = user.user_id;

  certMsg.verification_key = vrfkyKey;
  certMsg.server_signature = signature;

  ServerToUser_IssuedCertificate_Message issuedCertMsg;
  issuedCertMsg.certificate = certMsg;
  // std::cout << "USER ID TO SEND FROM SERVER ON LOGIN: " << issuedCertMsg.certificate.id;

  std::vector<unsigned char> issuedCertData;
  std::vector<unsigned char> encrypt_tag_IssuedCertData = crypto_driver->encrypt_and_tag(std::get<0>(keys), std::get<1>(keys), &issuedCertMsg);

  network_driver->send(encrypt_tag_IssuedCertData);
}

/**
 * Register the given user. This function should:
 * 1) Confirm that the user is not the database.
 * 2) Generate and send a salt and receives a hash of the salted password.
 * 3) Generate a pepper and store a second hash of the response + pepper.
 * 4) Generate and sends a PRG seed to the user
 * 5) Receive a 2FA response and verify it was generated in the last 60 seconds.
 * 6) Receive the user's verification key, and sign it to create a certificate.
 * 7) Store the user in the database.
 * @param id id of the user logging in
 * @param keys tuple of AES_key, HMAC_key corresponding to this session
 */
void ServerClient::HandleRegister(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  // TODO: implement me!
    // Step 1
    UserRow user = this->db_driver->find_user(id);
    if (user.user_id != "") {
      std::cout << "A user already exists in database with id: " << id << std::endl;
      network_driver->disconnect();
      throw std::runtime_error("A user already exists in database with id: " + id);
    }

    // Step 2
    SecByteBlock salt = crypto_driver->png(SALT_SIZE);
    ServerToUser_Salt_Message saltMsg;
    saltMsg.salt = byteblock_to_string(salt);
    std::vector<unsigned char> saltData;
    // saltMsg.serialize(saltData);

    std::vector<unsigned char> encrypt_tag_SaltData = crypto_driver->encrypt_and_tag(std::get<0>(keys), std::get<1>(keys), &saltMsg);

    // network_driver->send(saltData);

    network_driver->send(encrypt_tag_SaltData);

    UserToServer_HashedAndSaltedPassword_Message hashSaltPwdMsg;
    std::vector<unsigned char> hashSaltPwdData = network_driver->read();
        
    auto dec_vrfy_hashSaltPwd = crypto_driver->decrypt_and_verify(std::get<0>(keys), std::get<1>(keys), hashSaltPwdData);

    if (std::get<1>(dec_vrfy_hashSaltPwd) == false){
      std::cout << "Server could not decrypt/verify HashedAndSaltedPassword_Message." << std::endl;
      network_driver->disconnect();
      throw std::runtime_error("Server could not decrypt/verify HashedAndSaltedPassword_Message.");
    }
    // hashSaltPwdMsg.deserialize(hashSaltPwdData);
   
    hashSaltPwdMsg.deserialize(std::get<0>(dec_vrfy_hashSaltPwd));
  
    // Step 3
    SecByteBlock pepper = crypto_driver->png(PEPPER_SIZE);
    std::string passwordHash = crypto_driver->hash(hashSaltPwdMsg.hspw + byteblock_to_string(pepper));

    // Step 4
    SecByteBlock seed = crypto_driver->png(PRG_SIZE);
    ServerToUser_PRGSeed_Message seedMsg;
    seedMsg.seed = seed;
    std::vector<unsigned char> seedData;
    // seedMsg.serialize(seedData);
    
    std::vector<unsigned char> encrypt_tag_SeedData = crypto_driver->encrypt_and_tag(std::get<0>(keys), std::get<1>(keys), &seedMsg);

    // network_driver->send(seedData);
    network_driver->send(encrypt_tag_SeedData);

    // Step 5
    UserToServer_PRGValue_Message prgValMsg;
    std::vector<unsigned char> prgValData = network_driver->read();
      
    auto dec_vrfy_prgVal = crypto_driver->decrypt_and_verify(std::get<0>(keys), std::get<1>(keys), prgValData);

    if (std::get<1>(dec_vrfy_prgVal) == false){
      std::cout << "Server could not decrypt/verify PRGValue_Message." << std::endl;
      network_driver->disconnect();
      throw std::runtime_error("Server could not decrypt/verify PRGValue_Message.");
    }
    // prgValMsg.deserialize(prgValData);
    prgValMsg.deserialize(std::get<0>(dec_vrfy_prgVal));
    CryptoPP::SecByteBlock r = prgValMsg.value;

    Integer currTime = crypto_driver->nowish(); // Q: verify r that it was generated in last 60 seconds?
    bool validR = false;
    for (int i = 0; i < 60; ++i) {
      if (prgValMsg.value == crypto_driver->prg(seedMsg.seed, integer_to_byteblock(currTime - i), PRG_SIZE)){
        // found time within the past 60 seconds
        validR = true;
        break;
      }
    }
    if (!validR){
      std::cout << "This user's ceritficate has expired." << std::endl;
      network_driver->disconnect();
      throw std::runtime_error("This user's ceritficate has expired.");
    }


    // Step 6
    UserToServer_VerificationKey_Message vrfkyMsg;
    std::vector<unsigned char> vrfkyData = network_driver->read();
    
    auto dec_vrfy_vrfky = crypto_driver->decrypt_and_verify(std::get<0>(keys), std::get<1>(keys), vrfkyData);

    if (std::get<1>(dec_vrfy_vrfky) == false){
      std::cout << "Server could not decrypt/verify VerificationKey_Message." << std::endl;
      network_driver->disconnect();
      throw std::runtime_error("Server could not decrypt/verify VerificationKey_Message.");
    }

    // vrfkyMsg.deserialize(vrfkyData);
    vrfkyMsg.deserialize(std::get<0>(dec_vrfy_vrfky));
    CryptoPP::RSA::PublicKey vrfkyKey = vrfkyMsg.verification_key;

    std::vector<unsigned char> message = concat_string_and_rsakey(id, vrfkyKey);
    std::string signature = crypto_driver->RSA_sign(this->RSA_signing_key, message); 

    Certificate_Message certMsg;
    certMsg.id = id;
    // std::cout << "USER ID IN SERVER REGISTRATION: " << id;
    certMsg.verification_key = vrfkyKey;
    certMsg.server_signature = signature;

    ServerToUser_IssuedCertificate_Message issuedCertMsg;
    issuedCertMsg.certificate = certMsg;
    std::vector<unsigned char> issuedCertData;
    // issuedCertMsg.serialize(issuedCertData);
    
    std::vector<unsigned char> encrypt_tag_IssuedCertData = crypto_driver->encrypt_and_tag(std::get<0>(keys), std::get<1>(keys), &issuedCertMsg);
    // network_driver->send(issuedCertData);
    network_driver->send(encrypt_tag_IssuedCertData);

    // step 7
    UserRow newUser;
    newUser.user_id = id;
    newUser.password_hash = passwordHash;
    newUser.password_salt = saltMsg.salt;
    newUser.prg_seed = byteblock_to_string(seed);
    this->db_driver->insert_user(newUser);
}