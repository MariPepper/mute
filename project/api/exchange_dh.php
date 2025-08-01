<?php
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('Strict-Transport-Security: max-age=31536000');

if ($_SERVER['HTTPS'] !== 'on') {
    header('HTTP/1.1 403 Forbidden');
    error_log('Non-HTTPS request to exchange_dh.php');
    echo json_encode(['error' => 'HTTPS required']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
$passwordHash = $input['passwordHash'] ?? '';
$publicKey = $input['publicKey'] ?? null;

if (!preg_match('/^[0-9a-f]{64}$/i', $passwordHash)) {
    error_log("Invalid password hash received: " . $passwordHash);
    echo json_encode(['error' => 'Invalid password hash']);
    exit;
}

$modulus = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF';
$base = '2';

$privateDir = '../private';
if (!is_dir($privateDir)) {
    if (!mkdir($privateDir, 0700, true)) {
        error_log("Failed to create directory: $privateDir");
        echo json_encode(['error' => 'Server error: cannot create directory']);
        exit;
    }
}

$publicKeysFile = "$privateDir/public_keys_" . $passwordHash . ".json";
if (file_exists($publicKeysFile) && (time() - filemtime($publicKeysFile)) > 3600) {
    error_log("Cleaning up old public keys file: $publicKeysFile");
    unlink($publicKeysFile);
}
$publicKeys = file_exists($publicKeysFile) ? json_decode(file_get_contents($publicKeysFile), true) : [];

if ($publicKey !== null && $publicKey !== '') {
    if (!preg_match('/^\d+$/', $publicKey)) {
        error_log("Invalid public key received: " . $publicKey);
        echo json_encode(['error' => 'Invalid public key']);
        exit;
    }
    $publicKeys[] = $publicKey;
    if (!file_put_contents($publicKeysFile, json_encode($publicKeys, JSON_PRETTY_PRINT), LOCK_EX)) {
        error_log("Failed to write to $publicKeysFile");
        echo json_encode(['error' => 'Server error: cannot write public keys']);
        exit;
    }
    if (!chmod($publicKeysFile, 0600)) {
        error_log("Failed to set permissions on $publicKeysFile");
    }
    error_log("Saved public key to $publicKeysFile");
}

echo json_encode([
    'modulusHex' => $modulus,
    'base' => $base,
    'publicKeys' => $publicKeys
]);
?>
