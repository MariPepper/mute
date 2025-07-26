<?php
require_once 'masterkey.php';
require_once 'encrypt_json.php';

function regenerate_keys() {
    try {
        $masterKey = decryptMasterKey();
        $staticKey = getStaticKey($masterKey);
        regenerateMasterKey($staticKey);
        unlink('../private/json_key.bin'); // Force new static key with updated DF key
        return ['success' => true, 'message' => 'Keys regenerated successfully'];
    } catch (Exception $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

// Execute if called directly
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'])) {
    header('Content-Type: application/json');
    echo json_encode(regenerate_keys());
}
?>

