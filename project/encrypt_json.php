<?php
if (!defined('ENCRYPT_JSON_INCLUDED')) {
    define('ENCRYPT_JSON_INCLUDED', true);

    require_once 'masterkey.php';

    function getStaticKey($masterKey) {
        $keyFile = '../private/json_key.bin';
        $sessionFile = '../private/session_key.json';
        $logFile = '../private/key_log.txt';

        if (!file_exists($keyFile)) {
            $sessionData = file_exists($sessionFile) ? decryptJson(file_get_contents($sessionFile)) : [];
            $dfKey = base64_decode($sessionData['df_key'] ?? '');
            if ($dfKey) {
                $staticKey = deriveStaticKey($masterKey, $dfKey);
            } else {
                $staticKey = deriveStaticKey($masterKey);
            }
            $iv = random_bytes(12);
            $encrypted = openssl_encrypt($staticKey, 'aes-256-gcm', $masterKey, OPENSSL_RAW_DATA, $iv, $tag);
            if ($encrypted === false) {
                file_put_contents($logFile, date('Y-m-d H:i:s') . " - Static key encryption failed: " . openssl_error_string() . "\n", FILE_APPEND | LOCK_EX);
                throw new Exception('Static key encryption failed: ' . openssl_error_string());
            }
            file_put_contents($keyFile, json_encode([
                'iv' => base64_encode($iv),
                'tag' => base64_encode($tag),
                'encrypted_key' => base64_encode($encrypted),
                'created' => time()
            ]), LOCK_EX);
            chmod($keyFile, 0600);
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Created static key\n", FILE_APPEND | LOCK_EX);
        }

        $data = json_decode(file_get_contents($keyFile), true);
        if (!isset($data['encrypted_key'], $data['iv'], $data['tag'])) {
            unlink($keyFile);
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Corrupted json_key.bin; deleted for regeneration\n", FILE_APPEND | LOCK_EX);
            return getStaticKey($masterKey);
        }

        $staticKey = openssl_decrypt(
            base64_decode($data['encrypted_key']),
            'aes-256-gcm',
            $masterKey,
            OPENSSL_RAW_DATA,
            base64_decode($data['iv']),
            base64_decode($data['tag'])
        );
        if ($staticKey === false || strlen($staticKey) !== 32) {
            unlink($keyFile);
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Failed to decrypt json_key.bin or corrupted; deleted for regeneration\n", FILE_APPEND | LOCK_EX);
            return getStaticKey($masterKey);
        }
        return $staticKey;
    }

    function encryptJson($data) {
        $json = json_encode($data, JSON_PRETTY_PRINT);
        $iv = random_bytes(12);
        $masterKey = decryptMasterKey();
        $key = getStaticKey($masterKey);
        $encrypted = openssl_encrypt($json, 'AES-256-GCM', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($encrypted === false) {
            throw new Exception('Encryption failed: ' . openssl_error_string());
        }
        return base64_encode($iv . $tag . $encrypted);
    }

    function decryptJson($encrypted) {
        $data = base64_decode($encrypted);
        if ($data === false || strlen($data) < 28) {
            return [];
        }
        $iv = substr($data, 0, 12);
        $tag = substr($data, 12, 16);
        $ciphertext = substr($data, 28);
        $masterKey = decryptMasterKey();
        $key = getStaticKey($masterKey);
        $decrypted = openssl_decrypt($ciphertext, 'AES-256-GCM', $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($decrypted === false) {
            return [];
        }
        $decoded = json_decode($decrypted, true);
        return is_array($decoded) ? $decoded : [];
    }
}
?>