# mute
<img width="500" height="500" alt="svgviewer-png-output" src="https://github.com/user-attachments/assets/96cd0bd4-fca9-4dc6-bbb3-a26a6aeddf3c" />
<br>
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
    salt.bin: Salt for deriving the passKey (in the libsodium version of masterkey.php).
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

<img width="2880" height="7384" alt="mute_edr" src="https://github.com/user-attachments/assets/5b8f4687-ffae-46d8-8de1-65b28423cb1d" />
<br>
Client-Side / Ephemeral Keys

    chatkey
        Type: TTL: session
        Description: User's private secret key. Used for mandatory encryption; never stored server-side.

    key_hash
        Type: TTL: session
        Description: SHA-256 digest, used for session management (e.g., key revealing).

    derivedKey
        Type: TTL: session
        Description: PKDF2-derived key; used for encrypting private messages in term: salt_val.

    salt
        Type: TTL: Fixed (key for hash)
        Description: Random 16 bytes for PBKDF2 derivation, derived from user key hash.

    shareKey
        Type: TTL: 5 min
        Description: Current public key from session key, sim-DI-like refresh every 5 minutes.

Database Entities

    passphrase_txt
        Stores the root passphrase (24 characters) for user account: never created, never stored.

    master_key_bin
        Encrypts via AES-GCM and provides the key for the system's encryption.

    staticKey
        HMAC-SHA256 derived. Server JSON encrypts; stored encrypted in JSON.

    session_key_json
        Stores various public keys (chatkey), along with meta-like metadata and session management.

    df_key_mimicry
        Derived from master_key; used for direct user session-side to send messages directly.

    salt_key_mapping
        Maps cryptographic hashes to their unique salts for consistent PBKDF key derivation.

Key Relationships

    chatkey ↔ key_hash
        Key generation relation (SHA-256 key hashing).

    masterKey ↔ df_key_mimicry
        Direct mapping for session handling.

Encryption Usage

    derivedKey
        Private messages (temp_talk_gold_json).

    shareKey
        Public messages (temp_talk_silver_json).

Complete Key Derivation & Data Flow

    User Input: User provides chatkey → Generates key_hash.
    Salt Retrieval: Key_hash ↔ salt_key_mapping lookup.
    Private Key: PKDF2( chatKey, salt ) → Generates temp_talk_gold_json encryption.
    Server Master: Passphrase_txt → PassKey → AES-GCM decrypts master_key_bin.
    Session Pool: masterKey → session_key_json generation (TTL: 5 min).
    Public Key: session_key_json → shareKey (TTL: 5 min).
    Message Encryption: deriveKey → Encrypts messages (gold), shareKey encrypts public messages (silver).
    Auto Cleanup: 5-minute TTL cleanup for temp_talk_* tables.

Security Features & Architecture

    Multi-layer encryption for private vs public messaging.
    Key rotation designed for 5-minute refreshes.
    Persistent salt mapping for additional security across sessions.
    Database foreign keys ensure cascading protection.
    Built-in IP hash protection against data breaches. (optional/not implemented)

This structured overview encapsulates the architecture, focusing on key components, relationships, and security features of the MUTE system.
