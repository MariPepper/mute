<?php

if (!defined('MASTERKEY_INCLUDED')) {
    define('MASTERKEY_INCLUDED', true);

    // Sanity check
    if (!function_exists('sodium_crypto_pwhash')) {
        throw new Exception('Libsodium is not available. PHP >= 7.2 required.');
    }

    function derivePassKey($passphrase, $saltFile = '../private/salt.bin') {
        if (!file_exists($saltFile)) {
            $salt = random_bytes(16);
            file_put_contents($saltFile, $salt);
            chmod($saltFile, 0600);
        } else {
            $salt = file_get_contents($saltFile);
        }

        return sodium_crypto_pwhash(
            32, // 256-bit output
            $passphrase,
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
    }

    function generateMasterKey() {
        $keyFile = '../private/master_key.bin';
        $logFile = '../private/master_key_log.txt';
        if (file_exists($keyFile)) {
            return;
        }

        $passphrase = file_get_contents('../private/passphrase.txt');
        $passKey = derivePassKey($passphrase);

        $p = '323170060713110073003389139264238282488179412411402391128162675260996859168735390453461575873663185671139472590075092350419537715093615473918330810465662342918162805073389457172012151566751032774614255773761731625632701662592608080913693270404262565039086595173073393360515136047609632252159496700803752618477800464258095172405159520390026841863202393024625942058143646295615012414593693432976753456108132285174196855888270206121351269737563772341105297230074464222152176373992297694095529801399151321148784496944149268007346482149803364762149766117001862346671306655180398307321381454873523';
        $g = 2;

        $x = bin2hex(random_bytes(32));
        $x_gmp = gmp_init($x, 16);
        $randomNum = gmp_strval(gmp_powm($g, $x_gmp, gmp_init($p, 10)));

        $masterKey = hash('sha256', $randomNum, true);
        $iv = random_bytes(12);

        $encrypted = openssl_encrypt($masterKey, 'AES-256-GCM', $passKey, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($encrypted === false) {
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Master key encryption failed\n", FILE_APPEND | LOCK_EX);
            throw new Exception('Master key encryption failed');
        }

        $data = [
            'iv' => base64_encode($iv),
            'tag' => base64_encode($tag),
            'encrypted_key' => base64_encode($encrypted),
            'x' => $x,
            'created' => time()
        ];

        file_put_contents($keyFile, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
        chmod($keyFile, 0600);
        file_put_contents($logFile, date('Y-m-d H:i:s') . " - Created master key\n", FILE_APPEND | LOCK_EX);

        return $masterKey;
    }

    function decryptMasterKey() {
        $keyFile = '../private/master_key.bin';
        $logFile = '../private/master_key_log.txt';
        if (!file_exists($keyFile)) {
            return generateMasterKey();
        }

        $passphrase = file_get_contents('../private/passphrase.txt');
        $passKey = derivePassKey($passphrase);

        $data = json_decode(file_get_contents($keyFile), true);
        if (!isset($data['encrypted_key'], $data['iv'], $data['tag'])) {
            unlink($keyFile);
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Invalid master_key.bin; deleted\n", FILE_APPEND | LOCK_EX);
            return generateMasterKey();
        }

        $iv = base64_decode($data['iv']);
        $tag = base64_decode($data['tag']);
        $encrypted = base64_decode($data['encrypted_key']);

        $masterKey = openssl_decrypt($encrypted, 'AES-256-GCM', $passKey, OPENSSL_RAW_DATA, $iv, $tag);
        if ($masterKey === false || strlen($masterKey) !== 32) {
            unlink($keyFile);
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Decryption failed; file deleted\n", FILE_APPEND | LOCK_EX);
            return generateMasterKey();
        }

        return $masterKey;
    }

    function deriveStaticKey($masterKey, $dfKey = null) {
        $seed = $dfKey ?: 'static_key_seed';
        return hash_hmac('sha256', $seed, $masterKey, true);
    }

    function regenerateMasterKey($staticKey) {
        $keyFile = '../private/master_key.bin';
        $logFile = '../private/master_key_log.txt';

        $passphrase = file_get_contents('../private/passphrase.txt');
        $passKey = derivePassKey($passphrase);

        $p = '323170060713110073003389139264238282488179412411402391128162675260996859168735390453461575873663185671139472590075092350419537715093615473918330810465662342918162805073389457172012151566751032774614255773761731625632701662592608080913693270404262565039086595173073393360515136047609632252159496700803752618477800464258095172405159520390026841863202393024625942058143646295615012414593693432976753456108132285174196855888270206121351269737563772341105297230074464222152176373992297694095529801399151321148784496944149268007346482149803364762149766117001862346671306655180398307321381454873523';
        $g = 2;

        $x = bin2hex(hash('sha256', $staticKey, true));
        $x_gmp = gmp_init($x, 16);
        $randomNum = gmp_strval(gmp_powm($g, $x_gmp, gmp_init($p, 10)));

        $newMasterKey = hash('sha256', $randomNum, true);
        $iv = random_bytes(12);

        $encrypted = openssl_encrypt($newMasterKey, 'AES-256-GCM', $passKey, OPENSSL_RAW_DATA, $iv, $tag);
        if ($encrypted === false) {
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Regeneration failed: encryption error\n", FILE_APPEND | LOCK_EX);
            throw new Exception('Master key regeneration failed');
        }

        $data = [
            'iv' => base64_encode($iv),
            'tag' => base64_encode($tag),
            'encrypted_key' => base64_encode($encrypted),
            'x' => $x,
            'created' => time()
        ];

        file_put_contents($keyFile, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
        chmod($keyFile, 0600);
        file_put_contents($logFile, date('Y-m-d H:i:s') . " - Regenerated master key\n", FILE_APPEND | LOCK_EX);

        return $newMasterKey;
    }
}
?>
