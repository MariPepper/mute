<?php
header('Content-Type: application/json');
require_once 'encrypt_json.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['key_hash'])) {
    $keyHash = $_POST['key_hash'];
    $saltFile = '../private/salt_key_mapping.json';

    try {
        $data = file_exists($saltFile) ? decryptJson(file_get_contents($saltFile)) : [];
        if (!isset($data[$keyHash])) {
            $salt = base64_encode(random_bytes(16));
            $data[$keyHash] = $salt;
            file_put_contents($saltFile, encryptJson($data), LOCK_EX);
            chmod($saltFile, 0600);
        }
        echo json_encode(['salt' => $data[$keyHash]]);
    } catch (Exception $e) {
        error_log("Error in get_salt.php: " . $e->getMessage());
        echo json_encode(['error' => 'Failed to retrieve salt']);
    }
} else {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid request']);
}
?>