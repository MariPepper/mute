<?php
header('Content-Type: application/json');
require_once 'encrypt_json.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['key_hash'])) {
    $keyHash = $_POST['key_hash'];
    $saltFile = '../private/salt_key_mapping.json';
    $currentTime = time();

    try {
        // Load and clean key mappings
        $data = file_exists($saltFile) ? decryptJson(file_get_contents($saltFile)) : [];
        // Remove keys older than 1 day (86400 seconds)
        foreach ($data as $hash => $entry) {
            if (isset($entry['created']) && ($currentTime - $entry['created']) > 86400) {
                unset($data[$hash]);
                error_log("Removed expired key for hash: $hash");
            }
        }

        // If no key exists for this hash, generate a new salt and derive a key
        if (!isset($data[$keyHash])) {
            $salt = random_bytes(16); // 128-bit salt
            // Derive 256-bit key using PBKDF2 with SHA-512
            $highEntropyKey = hash_pbkdf2(
                'sha512', // Use SHA-512 for larger output and quantum resistance
                $keyHash, // Use key hash as password input
                $salt,
                1000000, // High iteration count
                32, // 256-bit key
                true // Raw binary output
            );
            $data[$keyHash] = [
                'salt' => base64_encode($salt),
                'key' => base64_encode($highEntropyKey),
                'created' => $currentTime
            ];
            file_put_contents($saltFile, encryptJson($data), LOCK_EX);
            chmod($saltFile, 0600);
            error_log("Generated high-entropy key for keyHash: $keyHash");
        }

        // Return the high-entropy key
        echo json_encode(['key' => $data[$keyHash]['key']]);
    } catch (Exception $e) {
        error_log("Error in get_salt.php: " . $e->getMessage());
        echo json_encode(['error' => 'Failed to retrieve or generate key']);
    }
} else {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid request']);
}
?>
