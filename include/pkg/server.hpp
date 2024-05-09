#pragma once

#include <iostream>
#include <utility>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/db_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "config.hpp"
#include "keyloaders.hpp"

// struct ThreadData {
//   int index;
//   std::shared_ptr<NetworkDriver> network_driver;
//   std::shared_ptr<CryptoDriver> crypto_driver;
//   CryptoPP::SecByteBlock aes;
//   CryptoPP::SecByteBlock hmac;
// };

class ServerClient {
public:
  ServerClient(ServerConfig server_config);
  void run(int port);
  bool HandleGCConnection(std::shared_ptr<NetworkDriver> network_driver,
                        std::shared_ptr<CryptoDriver> crypto_driver, int id);
  bool HandleConnection(std::shared_ptr<NetworkDriver> network_driver,
                        std::shared_ptr<CryptoDriver> crypto_driver);
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
  HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                    std::shared_ptr<CryptoDriver> crypto_driver);
  void
  HandleLogin(std::shared_ptr<NetworkDriver> network_driver,
              std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
              std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void HandleRegister(
      std::shared_ptr<NetworkDriver> network_driver,
      std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
      std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);

private:
  ServerConfig server_config;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<DBDriver> db_driver;

  CryptoPP::RSA::PrivateKey RSA_signing_key;
  CryptoPP::RSA::PublicKey RSA_verification_key;
  std::vector<std::tuple<SecByteBlock, std::string>> all_users_pk;
  
  void GenerateGCKey(std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, 
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys, 
    std::string my_id,
    int index);
  void ListenForConnections(int port);
  void Reset(std::string _);
  void Users(std::string _);
  void SendToAll(std::vector<unsigned char> data, int index);
  std::string GetKeys(std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, 
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> server_keys,
    int index);

  std::vector<std::shared_ptr<NetworkDriver>> threads;
  std::mutex mtx;
  int admin_index;
};
