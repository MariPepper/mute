# mute
<img width="500" height="500" alt="svgviewer-png-output" src="https://github.com/user-attachments/assets/96cd0bd4-fca9-4dc6-bbb3-a26a6aeddf3c" />

Based on the provided files, for the implementation of the MUTE chat system, you will need the following libraries, PHP version, and other requirements:
1. PHP Version and Required Extensions

PHP 7.2 or Higher:   
   gmp (GNU Multiple Precision) Extension: Essential for large number arithmetic operations (gmp_init, gmp_powm, gmp_strval, gmp_sub, gmp_mod) used in generating and regenerating master keys in masterkey.php and key generation in talk_silver.php.
    openssl Extension: Crucial for encryption functions (openssl_encrypt, openssl_decrypt, openssl_error_string, openssl_random_pseudo_bytes) used to encrypt and decrypt keys and JSON data in masterkey.php and encrypt_json.php, and to generate secure random bytes in talk_silver.php.
    json Extension: Necessary for encoding and decoding JSON data (json_encode, json_decode) that are widely used to store configurations, keys, and messages in files.
    hash Extension: Used for hashing functions (hash, hash_hmac, md5, sha256) in various files to derive keys, generate security hashes, and calculate key positions.
    random Extension (PHP 7.0+): For random_bytes and random_int used to generate secure random data, such as IVs, salts, and passphrases.

2. PHP Libraries (File Inclusions)

The provided PHP files already indicate internal dependencies through require_once:

    masterkey.php: Contains functions to generate, decrypt, and regenerate the master key.
    encrypt_json.php: Contains functions to obtain the static key, encrypt, and decrypt JSON data. This file, in turn, requires masterkey.php.
    regenerate_keys.php: Contains the logic to regenerate keys. This file requires masterkey.php and encrypt_json.php.
    simple_rotation.php: Includes regenerate_keys.php.
    get_salt.php: Requires encrypt_json.php.
    talk_gold.php and talk_silver.php: Both require encrypt_json.php.

3. Other Necessary Items for Implementation

Web Server:

    A web server like Apache or Nginx configured to serve PHP files.
    
Data Storage Directories:

    ../private/: This directory is crucial and should be configured to be inaccessible directly via the web. It will store sensitive files such as:
    session_key.json: Stores session keys and metadata for rotation.
    master_key.bin: Stores the encrypted master key.
    master_key_log.txt: Logs related to the master key.
    passphrase.txt: The passphrase used to derive the encryption key from the master key.
    salt.bin: Salt for deriving the passKey (see the libsodium version of masterkey.php).
    json_key.bin: Encrypted static key for JSON encryption.
    key_log.txt: Logs related to the static key.
    salt_key_mapping.json: Mapping of chat key hashes to salts.
    rotation_log.txt: Key rotation logs.
    chat_security.log: Chat security logs.
    
Temporary Message Directories:

    temp_talk_gold.json: Stores messages for the "Gold" chat (private).
    temp_talk_silver.json: Stores messages for the "Silver" chat (public).
    
Rate Limiting Directory:

    rate_limits/: To store rate limit control files by IP. (optional/not implemented)
    
File Permissions:

    Files within ../private/ and the files temp_talk_gold.json, temp_talk_silver.json, and the rate_limits/ directory should have write permissions for the web server user (e.g., www-data on Linux) but should not be publicly accessible. Permissions of 0600 (for files) and 0700 (for directories) are often used to restrict access.
    HTTPS Configuration: The system enforces the use of HTTPS, so you will need an SSL/TLS certificate configured for your domain.
    Timezone Configuration: It is recommended to set the default timezone for PHP (date_default_timezone_set()) to ensure consistency in timestamps.
    
Server Security:

    Protect the private Directory: Ensure that the ../private/ directory is outside the web document root or that the web server is configured to deny direct access to it.
    Error Logs: Monitor PHP and web server error logs to identify and resolve issues.
    Firewall and WAF: Implement a firewall and, if possible, a Web Application Firewall (WAF) to protect against common attacks.
    Regular Updates: Keep PHP, the web server, and all extensions updated to the latest versions to benefit from security patches.

In summary, the implementation requires a robust PHP environment with specific extensions for encryption and large number manipulation, along with careful configuration of directories and permissions to ensure the security of sensitive data.

<b>__________________________________________________________________________________________________________</b>

<b>MUTE Complete System Architecture Overview</b>

>> https://maripepper.github.io/mute/

<img width="2880" height="8038" alt="mute_edr" src="https://github.com/user-attachments/assets/ef0bdcc4-26ca-4f66-9a80-121ea558ddd6" />

Client-Side / Ephemeral Keys
- **chatKey**
 
   TTL: Session
   **Description**: User's private secret key. Used to generate `key_hash` and `derivedKey` for private chat encryption; never stored server-side.
- **key_hash**
 
   TTL: Session
   **Description**: SHA-256 digest of `chatKey`. Used to retrieve salt from `salt_key_mapping` for `derivedKey`.
- **derivedKey**
 
   TTL: Session
   **Description**: PBKDF2(`chatKey`, `salt_key_mapping.salt`, 100000, SHA-256) derived key; encrypts private messages in `temp_talk_gold_json`.

Server-Side / Ephemeral Keys
- **passKey**
 
   TTL: Transient
   **Description**: PBKDF2(`passphrase_txt.content`, `salt_bin.salt`, 100000, SHA-256); decrypts `master_key_bin` to get `masterKey`.
- **masterKey**
 
   TTL: Transient
   **Description**: Decrypted from `master_key_bin`; seeds `session_key_json.key_value` and derives `staticKey`.
- **staticKey**
 
   TTL: Transient (when not stored)
   **Description**: HMAC-SHA256(`masterKey`, `df_key_mimicry.df_key`); encrypts server JSON, stored in `json_key_bin`.

Database Entities
- **passphrase_txt**
 
   **Description**: Stores root passphrase (24 characters) for `passKey` derivation; 24-hour rotation.
- **master_key_bin**
 
   **Description**: Stores AES-GCM encrypted `masterKey`; used for system-wide key derivation; 24-hour rotation.
 **json_key_bin**
- 
   **Description**: Stores encrypted `staticKey` (HMAC-SHA256 derived); used for server JSON encryption; 24-hour rotation.
- **session_key_json**
 
   **Description**: Stores public `shareKey` (`key_value`) with Diffie-Hellman-like rotation; derives `df_key_mimicry.df_key`; 24-hour TTL, 5-minute windows.
- **df_key_mimicry**
 
   **Description**: Stores `df_key`, derived from `session_key_json.key_value` via SHA-256; seeds `staticKey`; 5-minute TTL.
- **salt_key_mapping**
 
   **Description**: Maps `key_hash` to salts for consistent `derivedKey` derivation; persistent TTL.
- **salt_bin**
 
   **Description**: Stores fixed salt for `passKey` derivation; persistent TTL.
- **temp_talk_gold_json**
 
   **Description**: Stores encrypted private messages (`derivedKey`); 5-minute TTL with auto-cleanup.
- **temp_talk_silver_json**
 
   **Description**: Stores encrypted public messages (`derived_key_silver`); 5-minute TTL with auto-cleanup.

Key Relationships
- **chatKey ↔ key_hash**
   **Description**: `key_hash` generated via SHA-256(`chatKey`) for salt lookup.
- **chatKey + salt_key_mapping.salt → derivedKey**
   **Description**: PBKDF2(`chatKey`, salt) derives `derivedKey` for private messages.
- **passphrase_txt.content + salt_bin.salt → passKey**
   **Description**: PBKDF2 derives `passKey` to decrypt `master_key_bin`.
- **masterKey → session_key_json.key_value**
   **Description**: `masterKey` seeds `shareKey` via Diffie-Hellman-like mechanism.
- **session_key_json.key_value → df_key_mimicry.df_key**
   **Description**: `shareKey` derives `df_key` via SHA-256(counter, time_window); FK: `session_key_id`.
- **masterKey + df_key_mimicry.df_key → staticKey**
   **Description**: HMAC-SHA256 derives `staticKey`; FKs: `master_key_id`, `df_key_mimicry_id`.
- **staticKey ↔ session_key_json**
   **Description**: `staticKey` encrypts/decrypts `session_key_json`; FK: `static_key_id`.
- **shareKey + per-message salt → derived_key_silver**
   **Description**: PBKDF2(`shareKey`, salt) derives `derived_key_silver` for public messages.

Encryption Usage
- **derivedKey**
   **Description**: Encrypts private messages in `temp_talk_gold_json` (AES).
- **derived_key_silver**
   **Description**: Encrypts public messages in `temp_talk_silver_json` (AES).
- **passKey**
   **Description**: Decrypts `master_key_bin` (AES-GCM).
- **staticKey**
   **Description**: Encrypts server JSON (e.g., `session_key_json`) (AES-GCM).

Complete Key Derivation & Data Flow
1. **User Input**: User provides `chatKey` → Generates `key_hash` via SHA-256.
2. **Salt Retrieval**: `key_hash` → `salt_key_mapping` lookup → Returns salt (or creates new pair).
3. **Private Key**: PBKDF2(`chatKey`, `salt_key_mapping.salt`) → `derivedKey` → AES encrypts `temp_talk_gold_json`.
4. **Server Master**: `passphrase_txt.content` + `salt_bin.salt` → PBKDF2 → `passKey` → AES-GCM decrypts `master_key_bin`.
5. **Static Key**: `masterKey` + `df_key_mimicry.df_key` → HMAC-SHA256 → `staticKey` → AES-GCM stores in `json_key_bin`.
6. **Session Pool**: `masterKey` → `session_key_json.key_value` (shareKey, DH-like, 5-minute windows).
7. **Public Key**: `session_key_json.key_value` → `shareKey` (5-minute TTL).
8. **DF Mimicry**: `shareKey` → SHA-256(counter, time_window) → `df_key_mimicry.df_key` → Seeds `staticKey`.
9. **Message Encryption**: `derivedKey` → AES encrypts `temp_talk_gold_json`; `shareKey` + salt → PBKDF2 → `derived_key_silver` → AES encrypts `temp_talk_silver_json`.
10. **Auto Cleanup**: 5-minute TTL for `temp_talk_*`, `df_key_mimicry`; 24-hour rotation for `passphrase_txt`, `master_key_bin`, `json_key_bin`.

Security Features & Architecture
- Multi-layer encryption: Private (`derivedKey`, AES) vs. public (`derived_key_silver`, AES) messages.
- Key rotation: 5-minute `shareKey` and `df_key_mimicry`; 24-hour `passphrase_txt`, `master_key_bin`, `json_key_bin`.
- Persistent salt mapping: `salt_key_mapping` ensures consistent `derivedKey`.
- Database foreign keys: Cascade via `passphrase_id`, `master_key_id`, `df_key_mimicry_id`, `session_key_id`, `static_key_id`, `salt_mapping_id`.
- Auto-cleanup TTLs: 5-minute purge for `temp_talk_*`, `df_key_mimicry`.
- AES-GCM authentication: IV/tag in `master_key_bin`, `json_key_bin` ensure integrity.
- IP hash moderation: `ip_hash` in `temp_talk_*` tracks abuse without PII.
- Forward secrecy: Diffie-Hellman-like `session_key_json` with 5-minute rotation.


This structured overview encapsulates the architecture, focusing on key components, relationships, and security features of the MUTE system.
