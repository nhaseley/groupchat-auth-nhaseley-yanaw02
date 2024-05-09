#include "../include-shared/messages.hpp"
#include "../include-shared/util.hpp"

// ================================================
// MESSAGE TYPES
// ================================================

/**
 * Get message type.
 */
MessageType::T get_message_type(std::vector<unsigned char> &data) {
  return (MessageType::T)data[0];
}

// ================================================
// SERIALIZERS
// ================================================

/**
 * Puts the bool b into the end of data.
 */
int put_bool(bool b, std::vector<unsigned char> &data) {
  data.push_back((char)b);
  return 1;
}

/**
 * Puts the string s into the end of data.
 */
int put_string(std::string s, std::vector<unsigned char> &data) {
  // Put length
  int idx = data.size();
  data.resize(idx + sizeof(size_t));
  size_t str_size = s.size();
  std::memcpy(&data[idx], &str_size, sizeof(size_t));

  // Put string
  data.insert(data.end(), s.begin(), s.end());
  return data.size() - idx;
}

/**
 * Puts the integer i into the end of data.
 */
int put_integer(CryptoPP::Integer i, std::vector<unsigned char> &data) {
  return put_string(CryptoPP::IntToString(i), data);
}

/**
 * Puts the next bool from data at index idx into b.
 */
int get_bool(bool *b, std::vector<unsigned char> &data, int idx) {
  *b = (bool)data[idx];
  return 1;
}

/**
 * Puts the next string from data at index idx into s.
 */
int get_string(std::string *s, std::vector<unsigned char> &data, int idx) {
  // Get length
  size_t str_size;
  std::memcpy(&str_size, &data[idx], sizeof(size_t));

  // Get string
  std::vector<unsigned char> svec(&data[idx + sizeof(size_t)],
                                  &data[idx + sizeof(size_t) + str_size]);
  *s = chvec2str(svec);
  return sizeof(size_t) + str_size;
}

/**
 * Puts the next integer from data at index idx into i.
 */
int get_integer(CryptoPP::Integer *i, std::vector<unsigned char> &data,
                int idx) {
  std::string i_str;
  int n = get_string(&i_str, data, idx);
  *i = CryptoPP::Integer(i_str.c_str());
  return n;
}

// ================================================
// WRAPPERS
// ================================================

/**
 * serialize HMACTagged_Wrapper.
 */
void HMACTagged_Wrapper::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::HMACTagged_Wrapper);

  // Add fields.
  put_string(chvec2str(this->payload), data);

  std::string iv = byteblock_to_string(this->iv);
  put_string(iv, data);

  put_string(this->mac, data);
}

/**
 * deserialize HMACTagged_Wrapper.
 */
int HMACTagged_Wrapper::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::HMACTagged_Wrapper);

  // Get fields.
  std::string payload_string;
  int n = 1;
  n += get_string(&payload_string, data, n);
  this->payload = str2chvec(payload_string);

  std::string iv;
  n += get_string(&iv, data, n);
  this->iv = string_to_byteblock(iv);

  n += get_string(&this->mac, data, n);
  return n;
}

/**
 * serialize Certificate_Message.
 */
void Certificate_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::Certificate_Message);

  // Serialize signing key.
  std::string verification_key_str;
  CryptoPP::StringSink ss(verification_key_str);
  this->verification_key.Save(ss);

  // Add fields.
  put_string(this->id, data);
  put_string(verification_key_str, data);
  put_string(this->server_signature, data);
}

/**
 * deserialize Certificate_Message.
 */
int Certificate_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::Certificate_Message);

  // Get fields.
  std::string verification_key_str;
  int n = 1;
  n += get_string(&this->id, data, n);
  n += get_string(&verification_key_str, data, n);
  n += get_string(&this->server_signature, data, n);

  // Deserialize signing key.
  CryptoPP::StringSource ss(verification_key_str, true);
  this->verification_key.Load(ss);
  return n;
}

// ================================================
// USER <=> SERVER MESSAGES
// ================================================

/**
 * serialize UserToServer_DHPublicValue_Message.
 */
void UserToServer_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_DHPublicValue_Message);

  // Add fields.
  std::string public_string = byteblock_to_string(this->public_value);
  put_string(public_string, data);
}

/**
 * deserialize UserToServer_DHPublicValue_Message.
 */
int UserToServer_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_DHPublicValue_Message);

  // Get fields.
  std::string public_string;
  int n = 1;
  n += get_string(&public_string, data, n);
  this->public_value = string_to_byteblock(public_string);
  return n;
}

/**
 * Serialize UserToServer_GC_DHPublicValue_Message.
 */
void UserToServer_GC_DHPublicValue_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_GC_DHPublicValue_Message);

  // Add fields.
  std::string key_string =
      byteblock_to_string(key);
  put_string(key_string, data);

  put_string(from_who, data);
  data.push_back(is_admin ? 1 : 0);
}

/**
 * Deserialize UserToServer_GC_DHPublicValue_Message.
 */
int UserToServer_GC_DHPublicValue_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  
  // assert(data[0] == MessageType::UserToServer_GC_DHPublicValue_Message);
  if (data[0] != MessageType::UserToServer_GC_DHPublicValue_Message) {
    // Print the message type before asserting
    std::cerr << "Unexpected message type: " << static_cast<int>(data[0]) << std::endl;
    assert(false); // Assertion fails
  }
  // Get fields.
  size_t pos = 1;
  
  // Deserialize key size
  size_t key_size;
  if (pos + sizeof(size_t) > data.size()) return -1;
  std::memcpy(&key_size, &data[pos], sizeof(size_t));
  pos += sizeof(size_t);
  if (data.size() < pos + key_size) return -1;
  
  // Deserialize key
  key.Assign(data.data() + pos, key_size);
  pos += key_size;

  // Deserialize from_who
  std::string from_who_string;
  int n = get_string(&from_who_string, data, pos);
  if (n < 0) return -1;
  from_who = from_who_string;
  pos += n;

  // Deserialize is_admin
  if (pos >= data.size()) return -1; // Ensure there's at least one more byte for is_admin
  is_admin = (data[pos] == 1);
  pos++;

  return pos;

}

/**
 * serialize ServerToUser_DHPublicValue_Message.
 */
void ServerToUser_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_DHPublicValue_Message);

  // Add fields.
  std::string server_public_string =
      byteblock_to_string(this->server_public_value);
  put_string(server_public_string, data);

  std::string user_public_string = byteblock_to_string(this->user_public_value);
  put_string(user_public_string, data);

  put_string(this->server_signature, data);

}

/**
 * deserialize ServerToUser_DHPublicValue_Message.
 */
int ServerToUser_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_DHPublicValue_Message);

  // Get fields.
  int n = 1;
  std::string server_public_string;
  n += get_string(&server_public_string, data, n);
  this->server_public_value = string_to_byteblock(server_public_string);

  std::string user_public_string;
  n += get_string(&user_public_string, data, n);
  this->user_public_value = string_to_byteblock(user_public_string);

  n += get_string(&this->server_signature, data, n);
  return n;
}

void put_int(int value, std::vector<unsigned char> &data) {
    data.push_back((value >> 24) & 0xFF);
    data.push_back((value >> 16) & 0xFF);
    data.push_back((value >> 8) & 0xFF);
    data.push_back(value & 0xFF);
}

int get_int(int &value, const std::vector<unsigned char> &data, int offset) {
    if (offset + 4 > data.size()) {
        throw std::runtime_error("Insufficient data for get_int");
    }

    value = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
    return 4;
}

/**
 * Serialize ServerToUser_GC_DHPublicValue_Message.
 */
void ServerToUser_GC_DHPublicValue_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
    data.push_back((char)MessageType::ServerToUser_GC_DHPublicValue_Message);

    // Add number of other_users_pk
    size_t num_users = other_users_pk.size();
    data.insert(data.end(), reinterpret_cast<const unsigned char*>(&num_users), reinterpret_cast<const unsigned char*>(&num_users) + sizeof(size_t));

    // Add each tuple of (SecByteBlock, std::string)
    for (const auto& tuple : other_users_pk) {
        const auto& sec_block = std::get<0>(tuple);
        const auto& str = std::get<1>(tuple);
        
        std::string sec_block_str = byteblock_to_string(sec_block);
        
        // Add size of SecByteBlock
        size_t sec_block_size = sec_block_str.size();
        data.insert(data.end(), reinterpret_cast<const unsigned char*>(&sec_block_size), reinterpret_cast<const unsigned char*>(&sec_block_size) + sizeof(size_t));

        // Add SecByteBlock
        data.insert(data.end(), sec_block_str.begin(), sec_block_str.end());

        // Add std::string
        put_string(str, data);
    }
}

/**
 * Deserialize ServerToUser_GC_DHPublicValue_Message.
 */
int ServerToUser_GC_DHPublicValue_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
    assert(data[0] == MessageType::ServerToUser_GC_DHPublicValue_Message);

    // Get number of other_users_pk
    size_t num_users;
    if (sizeof(size_t) + 1 > data.size()) return -1;
    std::memcpy(&num_users, &data[1], sizeof(size_t));

    size_t pos = sizeof(size_t) + 1;

    // Deserialize each tuple of (SecByteBlock, std::string)
    for (size_t i = 0; i < num_users; ++i) {
        // Deserialize SecByteBlock size
        size_t sec_block_size;
        if (pos + sizeof(size_t) > data.size()) return -1;
        std::memcpy(&sec_block_size, &data[pos], sizeof(size_t));
        pos += sizeof(size_t);

        // Deserialize SecByteBlock
        if (pos + sec_block_size > data.size()) return -1;
        CryptoPP::SecByteBlock sec_block(sec_block_size);
        sec_block.Assign(&data[pos], sec_block_size);
        pos += sec_block_size;

        // Deserialize std::string
        std::string str;
        int n = get_string(&str, data, pos);
        if (n < 0) return -1;
        pos += n;

        other_users_pk.emplace_back(sec_block, str);
    }

    return pos;

}

/**
 * Serialize UserToServer_GC_AdminPublicValue_Message. TODO: some repeated code for these 2 messages below
 */
void UserToServer_GC_AdminPublicValue_Message::serialize(std::vector<unsigned char> &data) {
    // Serialize pk_with_admin
    size_t pkSize = pk_with_admin.size();
    data.insert(data.end(), pk_with_admin.begin(), pk_with_admin.end());
    // Serialize R_iv
    size_t ivSize = R_iv.size();
    data.insert(data.end(), R_iv.begin(), R_iv.end());
    // Serialize R_ciphertext
    size_t ciphertextSize = R_ciphertext.size();
    data.insert(data.end(), R_ciphertext.begin(), R_ciphertext.end());
    // Serialize who_key_with
    size_t whoKeyWithSize = who_key_with.size();
    data.insert(data.end(), who_key_with.begin(), who_key_with.end());
    // Insert sizes of components
    data.push_back(static_cast<unsigned char>((pkSize >> 8) & 0xFF));
    data.push_back(static_cast<unsigned char>(pkSize & 0xFF));
    data.push_back(static_cast<unsigned char>((ivSize >> 8) & 0xFF));
    data.push_back(static_cast<unsigned char>(ivSize & 0xFF));
    data.push_back(static_cast<unsigned char>((ciphertextSize >> 8) & 0xFF));
    data.push_back(static_cast<unsigned char>(ciphertextSize & 0xFF));
    data.push_back(static_cast<unsigned char>((whoKeyWithSize >> 8) & 0xFF));
    data.push_back(static_cast<unsigned char>(whoKeyWithSize & 0xFF));
}

/**
 * Deserialize UserToServer_GC_AdminPublicValue_Message.
 */
int UserToServer_GC_AdminPublicValue_Message::deserialize(std::vector<unsigned char> &data) {
    size_t offset = 0;
    // Deserialize pk_with_admin
    size_t pkSize = (data[offset] << 8) + data[offset + 1];
    pk_with_admin.resize(pkSize);
    std::copy(data.begin() + offset + 2, data.begin() + offset + 2 + pkSize, pk_with_admin.begin());
    offset += pkSize + 2;
    // Deserialize R_iv
    size_t ivSize = (data[offset] << 8) + data[offset + 1];
    R_iv.resize(ivSize);
    std::copy(data.begin() + offset + 2, data.begin() + offset + 2 + ivSize, R_iv.begin());
    offset += ivSize + 2;
    // Deserialize R_ciphertext
    size_t ciphertextSize = (data[offset] << 8) + data[offset + 1];
    R_ciphertext.resize(ciphertextSize);
    std::copy(data.begin() + offset + 2, data.begin() + offset + 2 + ciphertextSize, R_ciphertext.begin());
    offset += ciphertextSize + 2;
    // Deserialize who_key_with
    size_t whoKeyWithSize = (data[offset] << 8) + data[offset + 1];
    who_key_with.resize(whoKeyWithSize);
    std::copy(data.begin() + offset + 2, data.begin() + offset + 2 + whoKeyWithSize, who_key_with.begin());
    offset += whoKeyWithSize + 2;
    // Return offset
    return offset;
}

/**
 * Serialize ServerToUser_GC_AdminPublicValue_Message.
 */
void ServerToUser_GC_AdminPublicValue_Message::serialize(std::vector<unsigned char> &data) {
    // Serialize pk_with_admin
    size_t pkSize = pk_with_admin.size();
    data.insert(data.end(), pk_with_admin.begin(), pk_with_admin.end());
    // Serialize R_iv
    size_t ivSize = R_iv.size();
    data.insert(data.end(), R_iv.begin(), R_iv.end());
    // Serialize R_ciphertext
    size_t ciphertextSize = R_ciphertext.size();
    data.insert(data.end(), R_ciphertext.begin(), R_ciphertext.end());
    // Serialize who_key_with
    size_t whoKeyWithSize = who_key_with.size();
    data.insert(data.end(), who_key_with.begin(), who_key_with.end());
    // Insert sizes of components
    data.push_back(static_cast<unsigned char>((pkSize >> 8) & 0xFF));
    data.push_back(static_cast<unsigned char>(pkSize & 0xFF));
    data.push_back(static_cast<unsigned char>((ivSize >> 8) & 0xFF));
    data.push_back(static_cast<unsigned char>(ivSize & 0xFF));
    data.push_back(static_cast<unsigned char>((ciphertextSize >> 8) & 0xFF));
    data.push_back(static_cast<unsigned char>(ciphertextSize & 0xFF));
    data.push_back(static_cast<unsigned char>((whoKeyWithSize >> 8) & 0xFF));
    data.push_back(static_cast<unsigned char>(whoKeyWithSize & 0xFF));
    
}

/**
 * Deserialize ServerToUser_GC_AdminPublicValue_Message.
 */
int ServerToUser_GC_AdminPublicValue_Message::deserialize(std::vector<unsigned char> &data) {
    size_t offset = 0;
    // Deserialize pk_with_admin
    size_t pkSize = (data[offset] << 8) + data[offset + 1];
    pk_with_admin.resize(pkSize);
    std::copy(data.begin() + offset + 2, data.begin() + offset + 2 + pkSize, pk_with_admin.begin());
    offset += pkSize + 2;
    // Deserialize R_iv
    size_t ivSize = (data[offset] << 8) + data[offset + 1];
    R_iv.resize(ivSize);
    std::copy(data.begin() + offset + 2, data.begin() + offset + 2 + ivSize, R_iv.begin());
    offset += ivSize + 2;
    // Deserialize R_ciphertext
    size_t ciphertextSize = (data[offset] << 8) + data[offset + 1];
    R_ciphertext.resize(ciphertextSize);
    std::copy(data.begin() + offset + 2, data.begin() + offset + 2 + ciphertextSize, R_ciphertext.begin());
    offset += ciphertextSize + 2;
    // Deserialize who_key_with
    size_t whoKeyWithSize = (data[offset] << 8) + data[offset + 1];
    who_key_with.resize(whoKeyWithSize);
    std::copy(data.begin() + offset + 2, data.begin() + offset + 2 + whoKeyWithSize, who_key_with.begin());
    offset += whoKeyWithSize + 2;
    // Return offset
    return offset;
}

/**
 * serialize UserToServer_IDPrompt_Message.
 */
void UserToServer_IDPrompt_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_IDPrompt_Message);

  // Add fields.
  put_string(this->id, data);
  put_bool(this->new_user, data);
}

/**
 * deserialize UserToServer_IDPrompt_Message.
 */
int UserToServer_IDPrompt_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_IDPrompt_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->id, data, n);
  n += get_bool(&this->new_user, data, n);
  return n;
}

/**
 * serialize ServerToUser_Salt_Message.
 */
void ServerToUser_Salt_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_Salt_Message);

  // Add fields.
  put_string(this->salt, data);
}

/**
 * deserialize ServerToUser_Salt_Message.
 */
int ServerToUser_Salt_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_Salt_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->salt, data, n);
  return n;
}

/**
 * serialize UserToServer_HashedAndSaltedPassword_Message.
 */
void UserToServer_HashedAndSaltedPassword_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back(
      (char)MessageType::UserToServer_HashedAndSaltedPassword_Message);

  // Add fields.
  put_string(this->hspw, data);
}

/**
 * deserialize UserToServer_HashedAndSaltedPassword_Message.
 */
int UserToServer_HashedAndSaltedPassword_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_HashedAndSaltedPassword_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->hspw, data, n);
  return n;
}

/**
 * serialize ServerToUser_PRGSeed_Message.
 */
void ServerToUser_PRGSeed_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_PRGSeed_Message);

  // Add fields.
  std::string seed_string = byteblock_to_string(this->seed);
  put_string(seed_string, data);
}

/**
 * deserialize ServerToUser_PRGSeed_Message.
 */
int ServerToUser_PRGSeed_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_PRGSeed_Message);

  // Get fields.
  std::string seed_string;
  int n = 1;
  n += get_string(&seed_string, data, n);
  this->seed = string_to_byteblock(seed_string);
  return n;
}

/**
 * serialize UserToServer_PRGValue_Message.
 */
void UserToServer_PRGValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_PRGValue_Message);

  // Add fields.
  std::string value_string = byteblock_to_string(this->value);
  put_string(value_string, data);
}

/**
 * deserialize UserToServer_PRGValue_Message.
 */
int UserToServer_PRGValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_PRGValue_Message);

  // Get fields.
  std::string value_string;
  int n = 1;
  n += get_string(&value_string, data, n);
  this->value = string_to_byteblock(value_string);
  return n;
}

void UserToServer_VerificationKey_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToServer_VerificationKey_Message);

  // Add fields.
  std::string verification_key_str;
  CryptoPP::StringSink ss(verification_key_str);
  this->verification_key.Save(ss);
  put_string(verification_key_str, data);
}

int UserToServer_VerificationKey_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToServer_VerificationKey_Message);

  // Get fields.
  std::string verification_key_str;
  int n = 1;
  n += get_string(&verification_key_str, data, n);

  // Deserialize key
  CryptoPP::StringSource ss(verification_key_str, true);
  this->verification_key.Load(ss);

  return n;
}

/**
 * serialize ServerToUser_IssuedCertificate_Message.
 */
void ServerToUser_IssuedCertificate_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::ServerToUser_IssuedCertificate_Message);

  // Add fields.
  std::vector<unsigned char> certificate_data;
  this->certificate.serialize(certificate_data);
  data.insert(data.end(), certificate_data.begin(), certificate_data.end());
}

/**
 * deserialize ServerToUser_IssuedCertificate_Message.
 */
int ServerToUser_IssuedCertificate_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::ServerToUser_IssuedCertificate_Message);

  // Get fields.
  int n = 1;
  std::vector<unsigned char> slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->certificate.deserialize(slice);

  return n;
}

// ================================================
// USER <=> USER MESSAGES
// ================================================

/**
 * serialize UserToUser_DHPublicValue_Message.
 */
void UserToUser_DHPublicValue_Message::serialize(
    std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToUser_DHPublicValue_Message);

  // Add fields.
  std::string value_string = byteblock_to_string(this->public_value);
  put_string(value_string, data);

  std::vector<unsigned char> certificate_data;
  this->certificate.serialize(certificate_data);
  data.insert(data.end(), certificate_data.begin(), certificate_data.end());

  put_string(this->user_signature, data);
}

/**
 * deserialize UserToUser_DHPublicValue_Message.
 */
int UserToUser_DHPublicValue_Message::deserialize(
    std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToUser_DHPublicValue_Message);

  // Get fields.
  std::string value_string;
  int n = 1;
  n += get_string(&value_string, data, n);
  this->public_value = string_to_byteblock(value_string);

  std::vector<unsigned char> slice =
      std::vector<unsigned char>(data.begin() + n, data.end());
  n += this->certificate.deserialize(slice);

  n += get_string(&this->user_signature, data, n);
  return n;
}

/**
 * serialize UserToUser_Message_Message.
 */
void UserToUser_Message_Message::serialize(std::vector<unsigned char> &data) {
  // Add message type.
  data.push_back((char)MessageType::UserToUser_Message_Message);

  // Add fields.
  put_string(this->msg, data);
}

/**
 * deserialize UserToUser_Message_Message.
 */
int UserToUser_Message_Message::deserialize(std::vector<unsigned char> &data) {
  // Check correct message type.
  assert(data[0] == MessageType::UserToUser_Message_Message);

  // Get fields.
  int n = 1;
  n += get_string(&this->msg, data, n);
  return n;
}

// ================================================
// SIGNING HELPERS
// ================================================

/**
 * Concatenate a string and a RSA public key into vector of unsigned char
 */
std::vector<unsigned char>
concat_string_and_rsakey(std::string &s, CryptoPP::RSA::PublicKey &k) {
  // Concat s to vec
  std::vector<unsigned char> v;
  v.insert(v.end(), s.begin(), s.end());

  // Concat k to vec
  std::string k_str;
  CryptoPP::StringSink ss(k_str);
  k.Save(ss);
  v.insert(v.end(), k_str.begin(), k_str.end());
  return v;
}

/**
 * Concatenate two byteblocks into vector of unsigned char
 */
std::vector<unsigned char> concat_byteblocks(CryptoPP::SecByteBlock &b1,
                                             CryptoPP::SecByteBlock &b2) {
  // Convert byteblocks to strings
  std::string b1_str = byteblock_to_string(b1);
  std::string b2_str = byteblock_to_string(b2);

  // Concat strings to vec
  std::vector<unsigned char> v;
  v.insert(v.end(), b1_str.begin(), b1_str.end());
  v.insert(v.end(), b2_str.begin(), b2_str.end());
  return v;
}

/**
 * Concatenate a byteblock and certificate into vector of unsigned char
 */
std::vector<unsigned char>
concat_byteblock_and_cert(CryptoPP::SecByteBlock &b,
                          Certificate_Message &cert) {
  // Convert byteblock to strings, serialize cert
  std::string b_str = byteblock_to_string(b);

  std::vector<unsigned char> cert_data;
  cert.serialize(cert_data);

  // Concat string and data to vec.
  std::vector<unsigned char> v;
  v.insert(v.end(), b_str.begin(), b_str.end());
  v.insert(v.end(), cert_data.begin(), cert_data.end());
  return v;
}