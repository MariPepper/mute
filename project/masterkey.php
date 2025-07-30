<?php
if (!defined('MASTERKEY_INCLUDED')) {
    define('MASTERKEY_INCLUDED', true);

    function derivePassKey($passphrase, $saltFile = null) {
        $saltFile = $saltFile ?: __DIR__ . '/../private/salt.bin';
        if (!file_exists($saltFile)) {
            $salt = random_bytes(16);
            if (file_put_contents($saltFile, $salt) === false) {
                throw new Exception("Failed to write salt to $saltFile");
            }
            if (!chmod($saltFile, 0600)) {
                throw new Exception("Failed to set permissions on $saltFile");
            }
        } else {
            $salt = file_get_contents($saltFile);
            if ($salt === false) {
                throw new Exception("Failed to read salt from $saltFile");
            }
            if (strlen($salt) !== 16) {
                error_log("Corrupted salt.bin detected at $saltFile. Regenerating salt file.");
                unlink($saltFile);
                return derivePassKey($passphrase, $saltFile);
            }
        }

        $iterations = 100000; // High iteration count for security; adjust if needed
        return hash_pbkdf2('sha256', $passphrase, $salt, $iterations, 32, true);
    }

    function generateMasterKey() {
        $keyFile = __DIR__ . '/../private/master_key.bin';
        $logFile = __DIR__ . '/../private/master_key_log.txt';
        if (file_exists($keyFile)) {
            return;
        }

        $passphraseFile = __DIR__ . '/../private/passphrase.txt';
        $passphrase = file_get_contents($passphraseFile);
        if ($passphrase === false) {
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Failed to read passphrase from $passphraseFile\n", FILE_APPEND | LOCK_EX);
            throw new Exception("Failed to read passphrase from $passphraseFile");
        }

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
            $error = openssl_error_string();
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Master key encryption failed: $error\n", FILE_APPEND | LOCK_EX);
            throw new Exception("Master key encryption failed: $error");
        }

        $data = [
            'iv' => base64_encode($iv),
            'tag' => base64_encode($tag),
            'encrypted_key' => base64_encode($encrypted),
            'x' => $x,
            'created' => time()
        ];

        if (file_put_contents($keyFile, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX) === false) {
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Failed to write master key to $keyFile\n", FILE_APPEND | LOCK_EX);
            throw new Exception("Failed to write master key to $keyFile");
        }
        if (!chmod($keyFile, 0600)) {
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Failed to set permissions on $keyFile\n", FILE_APPEND | LOCK_EX);
            throw new Exception("Failed to set permissions on $keyFile");
        }
        file_put_contents($logFile, date('Y-m-d H:i:s') . " - Created master key\n", FILE_APPEND | LOCK_EX);

        return $masterKey;
    }

    function decryptMasterKey() {
        $keyFile = __DIR__ . '/../private/master_key.bin';
        $logFile = __DIR__ . '/../private/master_key_log.txt';
        if (!file_exists($keyFile)) {
            return generateMasterKey();
        }

        $passphraseFile = __DIR__ . '/../private/passphrase.txt';
        $passphrase = file_get_contents($passphraseFile);
        if ($passphrase === false) {
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Failed to read passphrase from $passphraseFile\n", FILE_APPEND | LOCK_EX);
            throw new Exception("Failed to read passphrase from $passphraseFile");
        }

        $passKey = derivePassKey($passphrase);

        $data = json_decode(file_get_contents($keyFile), true);
        if ($data === null || !isset($data['encrypted_key'], $data['iv'], $data['tag'])) {
            unlink($keyFile);
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Invalid master_key.bin at $keyFile; deleted for regeneration\n", FILE_APPEND | LOCK_EX);
            return generateMasterKey();
        }

        $iv = base64_decode($data['iv']);
        $tag = base64_decode($data['tag']);
        $encrypted = base64_decode($data['encrypted_key']);

        if ($iv === false || $tag === false || $encrypted === false) {
            unlink($keyFile);
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Invalid base64 data in master_key.bin at $keyFile; deleted for regeneration\n", FILE_APPEND | LOCK_EX);
            return generateMasterKey();
        }

        $masterKey = openssl_decrypt($encrypted, 'AES-256-GCM', $passKey, OPENSSL_RAW_DATA, $iv, $tag);
        if ($masterKey === false || strlen($masterKey) !== 32) {
            $error = openssl_error_string();
            unlink($keyFile);
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Master key decryption failed: $error; deleted $keyFile for regeneration\n", FILE_APPEND | LOCK_EX);
            return generateMasterKey();
        }

        return $masterKey;
    }

    function deriveStaticKey($masterKey, $dfKey = null) {
        $seed = $dfKey ?: 'static_key_seed';
        return hash_hmac('sha256', $seed, $masterKey, true);
    }

    function regenerateMasterKey($staticKey) {
        $keyFile = __DIR__ . '/../private/master_key.bin';
        $logFile = __DIR__ . '/../private/master_key_log.txt';

        $passphraseFile = __DIR__ . '/../private/passphrase.txt';
        $passphrase = file_get_contents($passphraseFile);
        if ($passphrase === false) {
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Failed to read passphrase from $passphraseFile\n", FILE_APPEND | LOCK_EX);
            throw new Exception("Failed to read passphrase from $passphraseFile");
        }

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
            $error = openssl_error_string();
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Master key encryption failed during regeneration: $error\n", FILE_APPEND | LOCK_EX);
            throw new Exception("Master key encryption failed during regeneration: $error");
        }

        $data = [
            'iv' => base64_encode($iv),
            'tag' => base64_encode($tag),
            'encrypted_key' => base64_encode($encrypted),
            'x' => $x,
            'created' => time()
        ];

        if (file_put_contents($keyFile, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX) === false) {
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Failed to write master key to $keyFile during regeneration\n", FILE_APPEND | LOCK_EX);
            throw new Exception("Failed to write master key to $keyFile during regeneration");
        }
        if (!chmod($keyFile, 0600)) {
            file_put_contents($logFile, date('Y-m-d H:i:s') . " - Failed to set permissions on $keyFile during regeneration\n", FILE_APPEND | LOCK_EX);
            throw new Exception("Failed to set permissions on $keyFile during regeneration");
        }
        file_put_contents($logFile, date('Y-m-d H:i:s') . " - Regenerated master key\n", FILE_APPEND | LOCK_EX);

        return $newMasterKey;
    }
}
?>
