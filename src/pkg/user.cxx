#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <vector>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/user.hpp"

/**
 * Constructor. Loads server public key.
 */
UserClient::UserClient(std::shared_ptr<NetworkDriver> network_driver,
                       std::shared_ptr<CryptoDriver> crypto_driver,
                       UserConfig user_config) {

  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
  this->user_config = user_config;

  this->cli_driver->init();

  // Load server's key
  try {
    LoadRSAPublicKey(user_config.server_verification_key_path,
                     this->RSA_server_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading server keys; exiting");
    throw std::runtime_error("Client could not open server's keys.");
  }

  // Load keys
  try {
    LoadRSAPrivateKey(this->user_config.user_signing_key_path,
                      this->RSA_signing_key);
    LoadRSAPublicKey(this->user_config.user_verification_key_path,
                     this->RSA_verification_key);
    LoadCertificate(this->user_config.user_certificate_path, this->certificate);
    this->RSA_verification_key = this->certificate.verification_key;
    LoadPRGSeed(this->user_config.user_prg_seed_path, this->prg_seed);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading keys, you may consider "
                                    "registering or logging in again!");
  } catch (std::runtime_error &_) {
    this->cli_driver->print_warning("Error loading keys, you may consider "
                                    "registering or logging in again!");
  }
}

/**
 * Starts repl.
 */
void UserClient::run() {
  REPLDriver<UserClient> repl = REPLDriver<UserClient>(this);
  repl.add_action("login", "login <address> <port>",
                  &UserClient::HandleLoginOrRegister);
  repl.add_action("register", "register <address> <port>",
                  &UserClient::HandleLoginOrRegister);
  repl.add_action("listen", "listen <port>", &UserClient::HandleUser);
  repl.add_action("connect", "connect <address> <port>",
                  &UserClient::HandleUser);
  repl.add_action("gc", "gc <address> <port> <admin/user>", &UserClient::HandleGCMessage);
  repl.run();
}

void UserClient::HandleGCMessage(std::string input){
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 4)
  {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  std::string address = input_split[1];
  int port = std::stoi(input_split[2]);
  bool is_admin = (input_split[3] == "admin");
  this->network_driver->connect(address, port);
  this->DoMessageGC(is_admin);
}

void UserClient::DoMessageGC(bool is_admin)
{
  auto server_keys = this->HandleServerKeyExchange();
  // if (this->id == ''){
  //   this->cli_driver->print_left("You must first login.");
  // }
  this->id = this->user_config.user_username;

  CryptoPP::SecByteBlock gc_key = this->GenerateGCKey(is_admin, server_keys);
  std::cout << "GC KEY FINAL: " << byteblock_to_string(gc_key) << std::endl;
  this->cli_driver->init();
  this->cli_driver->print_success("Connected!");

  boost::thread msgListener =
      boost::thread(boost::bind(&UserClient::ReceiveRawThread, this));
  
  // *SOME ENCRYPT MESSAGE BEFORE SENDING MESSAGE* //
  // std::cout << "SENDING FROM USER: " << plaintext << std::endl;
  this->SendThread(server_keys);
  msgListener.join();
}

/**
 * ReceiveThread but does not check with keys.
 * Unsafe. Only okay because the messages will be encrypted prior to sending them to the server.
 */
void UserClient::ReceiveRawThread() {
  while (true) {
    std::vector<unsigned char> encrypted_msg_data;
    try {
      encrypted_msg_data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      this->cli_driver->print_info("Received EOF; closing connection.");
      return;
    }
    std::cout << "IN RECEIVE RAW THREAD" << std::endl;

    UserToUser_Message_Message u2u_msg;

    u2u_msg.deserialize(encrypted_msg_data);
    std::cout << "MESSAGE: " <<  u2u_msg.msg << std::endl;
    // *SOME DECRYPT MESSAGE IN ORDER TO SEND MESSAGE* //
    this->cli_driver->print_left(u2u_msg.msg);
  }
}

/**
* Function to do server's generate group chat key work, should be called for each thread with user
*
* 1. Generate my public key and send it to server
* 2. Receive other public keys from server
* 3. Generate next level of public keys using my private key: i.e. g^a => g^ab, g^ac
* 4. FOR ADMIN: 
*    a. Generate random R shared key
*    b. Use next level of public keys to encrypt R and send respectively to other users
*       i.e. User A sends [g^ab (R), B] to User B
*       and sends [g^ac (R), C] to User C
* 4. FOR OTHER USERS:
     a. Receive encryptions from server i.e. g^ab (R) and g^ac (R)
     b. Decrypt using respective next level of public keys 
        i.e. User C will reveal R by decrypting g^ac(R)
             User B will reveal R by decrypting g^ab(R)
* Shared key is now verified as R!
*
*/
CryptoPP::SecByteBlock UserClient::GenerateGCKey(bool is_admin, std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys){
  // Step 1
  std::cout << "ENTERING GenerateGCKey" << std::endl;
  SecByteBlock AESKey = std::get<0>(keys);
  SecByteBlock HMACKey =  std::get<1>(keys);

  // generating DH
  CryptoPP::Integer p = DL_P;
  CryptoPP::Integer q = DL_Q;
  std::tuple<DH, SecByteBlock, SecByteBlock> initializedParams = this->crypto_driver->DH_initialize();
  DH DH_obj = std::get<0>(initializedParams);
  SecByteBlock DH_private_value = std::get<1>(initializedParams);
  SecByteBlock DH_public_value = std::get<2>(initializedParams);
  std::cout << "USER: " << this->id << std::endl;
  // std::tuple<SecByteBlock, std::string> key_and_from_who = std::make_tuple(DH_public_value, this->id);
  UserToServer_GC_DHPublicValue_Message User_GC_PK_Msg;
  // User_GC_PK_Msg.key_and_from_who = key_and_from_who;

  // sending msg to server
  User_GC_PK_Msg.key = DH_public_value;
  User_GC_PK_Msg.from_who = this->id;
  User_GC_PK_Msg.is_admin = is_admin;

  // sending PK to server
  std::vector<unsigned char> User_GC_PK_Data = crypto_driver->encrypt_and_tag(AESKey, HMACKey, &User_GC_PK_Msg);
  this->network_driver->send(User_GC_PK_Data);

  std::cout << "Sent Public Key to server: " << byteblock_to_string(DH_public_value) << std::endl;
  std::cout << "Sent Public Key to server from: " << this->id << std::endl;

  // Step 2: get other gc pks
  ServerToUser_GC_DHPublicValue_Message Server_User_GC_PK_Msg;  
  std::cout << "ABOUT TO READ SERVER's PK MESSAGE" << std::endl;  
  std::vector<unsigned char> all_pk_data = network_driver->read();
  auto dec_vrfy_all_pk_data = crypto_driver->decrypt_and_verify(std::get<0>(keys), std::get<1>(keys), all_pk_data);
  if (std::get<1>(dec_vrfy_all_pk_data) == false){
    std::cout << "Server could not decrypt/verify ServerToUser_GC_DHPublicValue_Message" << std::endl;
    network_driver->disconnect();
    throw std::runtime_error("Server could not decrypt/verify ServerToUser_GC_DHPublicValue_Message");
  }
  Server_User_GC_PK_Msg.deserialize(std::get<0>(dec_vrfy_all_pk_data));
  std::vector<std::tuple<CryptoPP::SecByteBlock, std::string>> other_users_pk = Server_User_GC_PK_Msg.other_users_pk; // ex. (A, g^a)
  std::cout << "Reading other pks from server, size: " << other_users_pk.size() << std::endl;

  // Step 3
  std::string my_id = this->id;
  std::vector<std::tuple<SecByteBlock, std::string>> my_users_pk;
  std::copy_if(other_users_pk.begin(), other_users_pk.end(), std::back_inserter(my_users_pk),
    [&my_id](const auto& pk_and_user) { return std::get<1>(pk_and_user) != my_id; });
   std::vector<std::tuple<SecByteBlock, std::string>> other_users_updated_pk; // ex. (B, g^ab), (C, g^ac)
  for (const auto& pk_and_user : my_users_pk) {
    CryptoPP::SecByteBlock key = std::get<0>(pk_and_user);
    std::string id = std::get<1>(pk_and_user);
    std::cout << "PK: " << byteblock_to_string(key) << std::endl;
    std::cout << "User ID: " << id << std::endl;

    CryptoPP::Integer pk_int = byteblock_to_integer(key);
    CryptoPP::Integer priv_val_int = byteblock_to_integer(DH_private_value);
    std::cout << "PRIVATE: " << byteblock_to_string(integer_to_byteblock(priv_val_int));
    // Generate g^ab = (g^b)^a
    
    CryptoPP::SecByteBlock updated_key = this->crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, key);
    
    // CryptoPP::SecByteBlock updated_key = integer_to_byteblock(CryptoPP::ModularExponentiation(pk_int, priv_val_int, p));
    std::cout << "Updated key: " << byteblock_to_integer(updated_key) << std::endl;

    std::string new_id = id+my_id;
    std::tuple<SecByteBlock, std::string> updated_pk_and_user = std::make_tuple(updated_key, new_id);

    other_users_updated_pk.push_back(updated_pk_and_user);
  }
  
  // printing who with
  for (const auto& updated_pk_and_user : other_users_updated_pk) { // [g^ab, g^ac]
    std::cout << "ONE KEY WITH: " << std::get<1>(updated_pk_and_user) << std::endl;
  }

  // Step 4
  CryptoPP::Integer R;
  if (is_admin){
    CryptoPP::AutoSeededRandomPool prng;
    R = CryptoPP::Integer(prng, 2, q - 1);
    
    UserToServer_GC_AdminPublicValue_Message User_GC_AdminPublicValue_Msg;
    for (const auto& updated_pk_and_user : other_users_updated_pk) { // [g^ab, g^ac]
      SecByteBlock updated_pk = std::get<0>(updated_pk_and_user);
      std::string who_key_with = std::get<1>(updated_pk_and_user);
      std::cout << "UPDATED PK: " << byteblock_to_string(updated_pk) << std::endl;
      std::cout << "WHO KEY WITH User ID: " << who_key_with << std::endl;
      
      // Encrypt R with each updated_pk
      // ciphertext, iv TODO: FIX ENCRYPTION
      SecByteBlock temp_aes = this->crypto_driver->AES_generate_key(updated_pk);
      std::pair<std::string, SecByteBlock> encrypted = this->crypto_driver->AES_encrypt(temp_aes, byteblock_to_string(integer_to_byteblock(R)));
      std::string R_ciphertext = std::get<0>(encrypted); // get ciphertext
      SecByteBlock R_iv = std::get<1>(encrypted); // get iv

      std::cout << "SENDING R TO OTHER USERS: " << byteblock_to_string(integer_to_byteblock(R)) << std::endl;
      // Generate g^ab(R)
      std::string final_id = who_key_with;
      std::tuple<SecByteBlock, std::string> encrypted_R_with_user = std::make_tuple(string_to_byteblock(R_ciphertext), final_id);
      
      std::cout << "R_iv to send: " << byteblock_to_string(R_iv) << std::endl;
      std::cout << "R_ciphertext to send: " << R_ciphertext << std::endl;

      // adjust message to be sending the corresponding pk AND iv AND ciphertext
      User_GC_AdminPublicValue_Msg.pk_with_admin = updated_pk;
      User_GC_AdminPublicValue_Msg.R_iv = R_iv;
      User_GC_AdminPublicValue_Msg.R_ciphertext = R_ciphertext;
      User_GC_AdminPublicValue_Msg.who_key_with = who_key_with;
    }
    std::cout << "ABOUT TO SEND ENCRYPTED R" << std::endl;

    std::vector<unsigned char> User_GC_AdminPublicValue_Data = crypto_driver->encrypt_and_tag(AESKey, HMACKey, &User_GC_AdminPublicValue_Msg);
    this->network_driver->send(User_GC_AdminPublicValue_Data);
    std::cout << "JUST SEND ENCRYPTED R" << std::endl;


  } else {
    std::cout << "NOT ADMIN, PERFORMING DECRYPTIONS FOR R" << std::endl;
    bool found_my_pk_with_admin = false;
    
    ServerToUser_GC_AdminPublicValue_Message Server_GC_AdminPublicValue_Msg;
    int num_users = other_users_pk.size();
    
    for (int i = 0; i < num_users; ++i) {
      std::vector<unsigned char> Server_GC_AdminPublicValue_Data = this->network_driver->read();
      std::cout << "JUST READ AN ADMIN PV" << std::endl;

      
      // auto dec_vrfy_Server_GC_AdminPublicValue_Data = crypto_driver->decrypt_and_verify(std::get<0>(keys), std::get<1>(keys), Server_GC_AdminPublicValue_Data);
      // if (std::get<1>(dec_vrfy_Server_GC_AdminPublicValue_Data) == false){
      //   std::cout << "User could not decrypt/verify ServerToUser_GC_AdminPublicValue_Message" << std::endl;
      //   network_driver->disconnect();
      //   throw std::runtime_error("User could not decrypt/verify ServerToUser_GC_AdminPublicValue_Message");
      // }
      Server_GC_AdminPublicValue_Msg.deserialize(Server_GC_AdminPublicValue_Data);
      // for (int i=0; i < Server_GC_AdminPublicValue_Msg.who_key_with.size(); ++i){
      std::cout << "WHO KEY WITH: " << Server_GC_AdminPublicValue_Msg.who_key_with << std::endl;
      // }
      // if (Server_GC_AdminPublicValue_Msg.who_key_with == this->id){ // found g^ac for user c or g^ab for user b
      if (Server_GC_AdminPublicValue_Msg.who_key_with.find(this->id) != std::string::npos) {
        std::cout << "found_my_pk_with_admin in here: " << Server_GC_AdminPublicValue_Msg.who_key_with << std::endl;
        std::cout << "found_my_pk_with_admin in here AND SHARED KEY: " << byteblock_to_string(Server_GC_AdminPublicValue_Msg.pk_with_admin) << std::endl;
        std::cout << "found_my_pk_with_admin in here AND IV: " << byteblock_to_string(Server_GC_AdminPublicValue_Msg.R_iv) << std::endl;
        std::cout << "found_my_pk_with_admin in here AND CIPHERTEXT: " << Server_GC_AdminPublicValue_Msg.R_ciphertext << std::endl;
        found_my_pk_with_admin = true;
        break;
      }
    }
    if (!found_my_pk_with_admin){
      std::cout << "KEY WITH ADMIN FOR ID " << this->id << " NOT FOUND." << std::endl;
      throw std::runtime_error("KEY WITH ADMIN FOR ID " + this->id + " not found.");
    }
    SecByteBlock key_with_admin = this->crypto_driver->AES_generate_key(Server_GC_AdminPublicValue_Msg.pk_with_admin);
    SecByteBlock R_iv = Server_GC_AdminPublicValue_Msg.R_iv; // used to decrypt R
    std::string R_ciphertext = Server_GC_AdminPublicValue_Msg.R_ciphertext; 
    
    std::string R_decrypted = this->crypto_driver->AES_decrypt(key_with_admin, R_iv, R_ciphertext);
    std::cout << "R DECRYPTED: " << R_decrypted << std::endl;
    CryptoPP::Integer R = byteblock_to_integer(string_to_byteblock(R_decrypted));
  }
  std::cout << "returning R: " << byteblock_to_string(integer_to_byteblock(R)) << std::endl;

  return integer_to_byteblock(R);
}


/**
 * Diffie-Hellman key exchange with server. This function should:
 * 1) Generate a keypair, a, g^a and send it to the server.
 * 2) Receive a public value (g^a, g^b) from the server and verify its
 * signature.
 * 3) Verify that the public value the server received is g^a.
 * 4) Generate a DH shared key and generate AES and HMAC keys.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::HandleServerKeyExchange() {
  // TODO: implement me!
  // Step 1
  std::tuple<DH, SecByteBlock, SecByteBlock> initializedParams = this->crypto_driver->DH_initialize();
  DH DH_obj = std::get<0>(initializedParams);
  SecByteBlock DH_private_value = std::get<1>(initializedParams);
  SecByteBlock DH_public_value = std::get<2>(initializedParams);

  std::vector<unsigned char> data;
  UserToServer_DHPublicValue_Message userDHMsg;
  std::vector<unsigned char> userDHData;
  userDHMsg.public_value = DH_public_value;
  
  userDHMsg.serialize(userDHData);
  this->network_driver->send(userDHData);
  
  // Step 2
  ServerToUser_DHPublicValue_Message serverDHMsg;
  std::vector<unsigned char> serverDHData = this->network_driver->read();
  serverDHMsg.deserialize(serverDHData);
  
  std::vector<unsigned char> message = concat_byteblocks(serverDHMsg.server_public_value, userDHMsg.public_value);

  // Step 3
  if (serverDHMsg.user_public_value != DH_public_value){
    std::cout << "Public value sent from server is not g^a during ServerKeyExchange." << std::endl;
    this->network_driver->disconnect();
    throw std::runtime_error("Public value sent from server is not g^a during ServerKeyExchange");
  }
  if (!this->crypto_driver->RSA_verify(this->RSA_server_verification_key, message, serverDHMsg.server_signature)){
    std::cout << "RSA Verification error during Server Key Exchange." << std::endl;
    this->network_driver->disconnect();
    throw std::runtime_error("RSA Verification error during Server Key Exchange.");
  }

  // Step 4
  SecByteBlock shared_key = this->crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, serverDHMsg.server_public_value);
  SecByteBlock AESKey = this->crypto_driver->AES_generate_key(shared_key);
  SecByteBlock HMACKey = this->crypto_driver->HMAC_generate_key(shared_key);

  return std::make_pair(AESKey, HMACKey);
}

/**
 * Diffie-Hellman key exchange with another user. This function shuold:
 * 1) Generate a keypair, a, g^a, signs it, and sends it to the other user.
 *    Use concat_byteblock_and_cert to sign the message.
 * 2) Receive a public value from the other user and verifies its signature and
 * certificate.
 * 3) Generate a DH shared key and generate AES and HMAC keys.
 * 4) Store the other user's verification key in RSA_remote_verification_key.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::HandleUserKeyExchange() {
  // TODO: implement me!

  // Step 1
  std::tuple<DH, SecByteBlock, SecByteBlock> initializedParams = crypto_driver->DH_initialize();
  DH DH_obj = std::get<0>(initializedParams);
  SecByteBlock DH_private_value = std::get<1>(initializedParams);
  SecByteBlock DH_public_value = std::get<2>(initializedParams);

  Certificate_Message certificate = this->certificate;
  std::string signature = this->crypto_driver->RSA_sign(this->RSA_signing_key, concat_byteblock_and_cert(DH_public_value, certificate));

  UserToUser_DHPublicValue_Message userDHMsg;
  std::vector<unsigned char> userDHData;
  userDHMsg.public_value = DH_public_value;
  userDHMsg.certificate = certificate;
  // std::cout << "MY CERTIFICATE'S ID: " << userDHMsg.certificate.id;
  userDHMsg.user_signature = signature;
  userDHMsg.serialize(userDHData);
  this->network_driver->send(userDHData);

  // Step 2
  UserToUser_DHPublicValue_Message otherUserDHMsg;
  std::vector<unsigned char> otherUserDHData = this->network_driver->read();
  otherUserDHMsg.deserialize(otherUserDHData);

  std::vector<unsigned char> message = concat_byteblock_and_cert(otherUserDHMsg.public_value, otherUserDHMsg.certificate);
  // std::cout << "Other user pv in handleUserKE: " << byteblock_to_string(otherUserDHMsg.public_value) << std::endl;

  // std::string test = "HERE: ";
  // std::cout << "Other user verification key in handleUserKE: " << chvec2str(concat_string_and_rsakey(test, otherUserDHMsg.certificate.verification_key)) << std::endl;
  // std::cout << "Other user signature in handleUserKE: " << otherUserDHMsg.user_signature << std::endl;
  // std::cout << "Other server signature in handleUserKE: " << otherUserDHMsg.certificate.server_signature << std::endl;
  // std::cout << "Other user id in handleUserKE: " << otherUserDHMsg.certificate.id << std::endl;

  if (this->crypto_driver->RSA_verify(otherUserDHMsg.certificate.verification_key, message, otherUserDHMsg.user_signature) == false){
    std::cout << "Could not verify other user's certificate sent in HandleUserKeyExchange." << std::endl;
    this->network_driver->disconnect();
    throw std::runtime_error("Could not verify other user's certificate sent in HandleUserKeyExchange.");
  }
  
  std::vector<unsigned char> message2 = concat_string_and_rsakey(otherUserDHMsg.certificate.id, otherUserDHMsg.certificate.verification_key);
  
  // std::string test = "SERVER RSA VRKFY";
  // std::cout << chvec2str(concat_string_and_rsakey(test, this->RSA_server_verification_key)) << std::endl;
  
  if (!this->crypto_driver->RSA_verify(this->RSA_server_verification_key, message2, otherUserDHMsg.certificate.server_signature)){
    std::cout << "Could not verify other user's id sent in HandleUserKeyExchange." << std::endl;
    this->network_driver->disconnect();
    throw std::runtime_error("Could not verify other user's id sent in HandleUserKeyExchange.");
  }

  // Step 3
  SecByteBlock shared_key = this->crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, otherUserDHMsg.public_value);
  SecByteBlock AESKey = this->crypto_driver->AES_generate_key(shared_key);
  SecByteBlock HMACKey = this->crypto_driver->HMAC_generate_key(shared_key);

  // Step 4
  this->RSA_remote_verification_key = otherUserDHMsg.certificate.verification_key;
  // this->network_driver->disconnect();
  return std::make_pair(AESKey, HMACKey);
  // Q: using Message_Message at all?
  
}

/**
 * User login or register.
 */
void UserClient::HandleLoginOrRegister(std::string input) {
  // Connect to server and check if we are registering.
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 3) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  std::string address = input_split[1];
  int port = std::stoi(input_split[2]);
  this->network_driver->connect(address, port);
  this->DoLoginOrRegister(input_split[0]);
}

/**
 * User login or register. This function should:
 * 1) Handles key exchange with the server.
 * 2) Tells the server our ID and intent.
 * 3) Receives a salt from the server.
 * 4) Generates and sends a hashed and salted password.
 * 5) (if registering) Receives a PRG seed from the server, store in
 * this->prg_seed.
 * 6) Generates and sends a 2FA response.
 * 7) Generates a RSA keypair, and send vk to the server for signing.
 * 8) Receives and save cert in this->certificate.
 * 9) Receives and saves the keys, certificate, and prg seed.
 * Remember to store RSA keys in this->RSA_signing_key and
 * this->RSA_verification_key
 */
void UserClient::DoLoginOrRegister(std::string input) {
  // TODO: implement me!

  // Step 1
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys = HandleServerKeyExchange();
  SecByteBlock AESKey = std::get<0>(keys);
  SecByteBlock HMACKey =  std::get<1>(keys);

  // Step 2
  UserToServer_IDPrompt_Message msg;
  this->id = this->user_config.user_username;
  msg.id = this->id;
  if (input == "register"){
    msg.new_user = true;
  } else {
    msg.new_user = false;
  }
  // std::vector<unsigned char> idData;
  // msg.serialize(idData);

  std::vector<unsigned char> encrypt_tag_IdData = crypto_driver->encrypt_and_tag(AESKey, HMACKey, &msg);
  // std::cout << "ID FROM USER IN LOGIN/REGISTER TO SERVER: " << msg.id << std::endl;
  this->network_driver->send(encrypt_tag_IdData);

  // Step 3
  ServerToUser_Salt_Message saltMsg;
  std::vector<unsigned char> saltData = this->network_driver->read();

  auto dec_vrfy_Salt = this->crypto_driver->decrypt_and_verify(AESKey, HMACKey, saltData);

  if (std::get<1>(dec_vrfy_Salt) == false){
    std::cout << "User could not decrypt/verify Salt_Message." << std::endl;
    this->network_driver->disconnect();
    throw std::runtime_error("User could not decrypt/verify Salt_Message.");
  }
  
  // saltMsg.deserialize(saltData);
  saltMsg.deserialize(std::get<0>(dec_vrfy_Salt));
  
  // Step 4
  UserToServer_HashedAndSaltedPassword_Message hashSaltPwdMsg;
  
  hashSaltPwdMsg.hspw = this->crypto_driver->hash(this->user_config.user_password + saltMsg.salt);
  // std::vector<unsigned char> hashSaltPwdData;
  // hashSaltPwdMsg.serialize(hashSaltPwdData);
  
  std::vector<unsigned char> encrypt_tag_hashSaltPwdData = crypto_driver->encrypt_and_tag(AESKey, HMACKey, &hashSaltPwdMsg);
  // this->network_driver->send(hashSaltPwdData);
  this->network_driver->send(encrypt_tag_hashSaltPwdData);

  // Step 5
  if (input == "register"){
    ServerToUser_PRGSeed_Message prgSeedMsg;
    std::vector<unsigned char> prgSeedData = this->network_driver->read();

    auto dec_vrfy_prgSeed = this->crypto_driver->decrypt_and_verify(AESKey, HMACKey, prgSeedData);

    if (std::get<1>(dec_vrfy_prgSeed) == false){
      std::cout << "User could not decrypt/verify PRGSeed_Message." << std::endl;
      this->network_driver->disconnect();
      throw std::runtime_error("User could not decrypt/verify PRGSeed_Message.");
    }

    // prgSeedMsg.deserialize(prgSeedData);
    prgSeedMsg.deserialize(std::get<0>(dec_vrfy_prgSeed));
    this->prg_seed = prgSeedMsg.seed;
  }

  // Step 6
  Integer currTime = this->crypto_driver->nowish();
  UserToServer_PRGValue_Message prgValMsg;
  prgValMsg.value = this->crypto_driver->prg(this->prg_seed, integer_to_byteblock(currTime), PRG_SIZE);
  std::vector<unsigned char> prgValData;
  prgValMsg.serialize(prgValData);
  
  std::vector<unsigned char> encrypt_tag_prgValData = crypto_driver->encrypt_and_tag(AESKey, HMACKey, &prgValMsg);
  // this->network_driver->send(prgValData);
  this->network_driver->send(encrypt_tag_prgValData);
  // std::cout << "ENCRYPTED PRG VAL: " << chvec2str(encrypt_tag_prgValData) << std::endl;

  // Step 7
  std::pair<RSA::PrivateKey, RSA::PublicKey> RSAKeys = this->crypto_driver->RSA_generate_keys();
  RSA::PrivateKey rsaPrivateKey = std::get<0>(RSAKeys);
  RSA::PublicKey rsaPublicKey = std::get<1>(RSAKeys);
  
  UserToServer_VerificationKey_Message vrfkyMsg;
  vrfkyMsg.verification_key = rsaPublicKey;
  std::vector<unsigned char> vrfkyData;
  vrfkyMsg.serialize(vrfkyData);
  
  std::vector<unsigned char> encrypt_tag_vrfkyData = crypto_driver->encrypt_and_tag(AESKey, HMACKey, &vrfkyMsg);
  // this->network_driver->send(vrfkyData);
  this->network_driver->send(encrypt_tag_vrfkyData);

  // Step 8
  ServerToUser_IssuedCertificate_Message certMsg;
  std::vector<unsigned char> certMsgData = this->network_driver->read();
  
  auto dec_vrfy_certMsgData = this->crypto_driver->decrypt_and_verify(AESKey, HMACKey, certMsgData);

  if (std::get<1>(dec_vrfy_certMsgData) == false){
    std::cout << "User could not decrypt/verify IssuedCertificate_Message." << std::endl;
    this->network_driver->disconnect();
    throw std::runtime_error("User could not decrypt/verify IssuedCertificate_Message.");
  }
  // certMsg.deserialize(certMsgData);
  certMsg.deserialize(std::get<0>(dec_vrfy_certMsgData));
  this->certificate = certMsg.certificate;

  // Step 9
  this->RSA_signing_key = rsaPrivateKey;
  this->RSA_verification_key = rsaPublicKey;

  SaveCertificate(this->user_config.user_certificate_path, this->certificate);
  if (input == "register"){  
    SaveRSAPrivateKey(this->user_config.user_signing_key_path, this->RSA_signing_key);
    SaveRSAPublicKey(this->user_config.user_verification_key_path, this->RSA_verification_key);
    SavePRGSeed(this->user_config.user_prg_seed_path, this->prg_seed);
  }
  this->network_driver->disconnect();
}

/**
 * Handles communicating with another user. This function
 * 1) Prompts the CLI to see if we're registering or logging in.
 * 2) Handles key exchange with the other user.
 */
void UserClient::HandleUser(std::string input) {
  // Handle if connecting or listening; parse user input.
  std::vector<std::string> args = string_split(input, ' ');
  bool isListener = args[0] == "listen";
  if (isListener) {
    if (args.size() != 2) {
      this->cli_driver->print_warning("Invalid args, usage: listen <port>");
      return;
    }
    int port = std::stoi(args[1]);
    this->network_driver->listen(port);
  } else {
    if (args.size() != 3) {
      this->cli_driver->print_warning(
          "Invalid args, usage: connect <ip> <port>");
      return;
    }
    std::string ip = args[1];
    int port = std::stoi(args[2]);
    this->network_driver->connect(ip, port);
  }

  // Exchange keys.
  auto keys = this->HandleUserKeyExchange();

  // Clear the screen
  this->cli_driver->init();
  this->cli_driver->print_success("Connected!");

  // Set up communication
  boost::thread msgListener =
      boost::thread(boost::bind(&UserClient::ReceiveThread, this, keys));
  this->SendThread(keys);
  msgListener.join();
}

/**
 * Listen for messages and print to CLI.
 */
void UserClient::ReceiveThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  while (true) {
    std::vector<unsigned char> encrypted_msg_data;
    try {
      encrypted_msg_data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      this->cli_driver->print_info("Received EOF; closing connection.");
      return;
    }
    // Check if HMAC is valid.
    auto msg_data = this->crypto_driver->decrypt_and_verify(
        keys.first, keys.second, encrypted_msg_data);
    if (!msg_data.second) {
      this->cli_driver->print_warning(
          "Invalid MAC on message; closing connection.");
      this->network_driver->disconnect();
      throw std::runtime_error("User sent message with invalid MAC.");
    }

    // // Decrypt and print.
    UserToUser_Message_Message u2u_msg;
    // u2u_msg.deserialize(msg_data.first);
    u2u_msg.deserialize(encrypted_msg_data);
    this->cli_driver->print_left(u2u_msg.msg);
  }
}

/**
 * Listen for stdin and send to other party.
 */
void UserClient::SendThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  std::string plaintext;
  while (std::getline(std::cin, plaintext)) {
    // Read from STDIN.
    if (plaintext != "") {
      std::cout << "IN SENDTHREAD" << std::endl;
      UserToUser_Message_Message u2u_msg;

      u2u_msg.msg = plaintext;
      std::cout << "PLAINTEXT IN SEND THREAD: " << plaintext << std::endl;

      std::vector<unsigned char> msg_data =
          this->crypto_driver->encrypt_and_tag(keys.first, keys.second,
                                               &u2u_msg);
      try {
        this->network_driver->send(msg_data);
      } catch (std::runtime_error &_) {
        this->cli_driver->print_info(
            "Other side is closed, closing connection");
        this->network_driver->disconnect();
        return;
      }
    }
    this->cli_driver->print_right(plaintext);
  }
  this->cli_driver->print_info("Received EOF from user; closing connection");
  this->network_driver->disconnect();
}
