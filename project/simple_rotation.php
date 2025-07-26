<?php
// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'regenerate_keys.php'; // Include key regeneration logic

// Log function
function log_action($message) {
    $logFile = '../private/rotation_log.txt';
    file_put_contents($logFile, date('Y-m-d H:i:s') . " - $message\n", FILE_APPEND | LOCK_EX);
}

// Generate a random 24-character passphrase
function generate_passphrase($length = 24) {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+';
    $passphrase = '';
    for ($i = 0; $i < $length; $i++) {
        $passphrase .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $passphrase;
}

// Main function to update passphrase and delete session key
function perform_rotation() {
    $passphraseFile = '../private/passphrase.txt';
    $sessionKeyFile = '../private/session_key.json';
    
    try {
        // Generate new passphrase
        $newPassphrase = generate_passphrase(24);
        log_action("Generated new 24-character passphrase");
        
        // Write new passphrase to file
        if (!file_put_contents($passphraseFile, $newPassphrase, LOCK_EX)) {
            throw new Exception("Failed to write to passphrase.txt");
        }
        chmod($passphraseFile, 0600);
        log_action("Updated passphrase.txt");
        
        // Delete session key file if it exists
        if (file_exists($sessionKeyFile)) {
            if (unlink($sessionKeyFile)) {
                log_action("Deleted session_key.json");
            } else {
                throw new Exception("Failed to delete session_key.json");
            }
        } else {
            log_action("session_key.json does not exist, nothing to delete");
        }
        
        return ['success' => true, 'message' => 'Rotation completed successfully'];
    } catch (Exception $e) {
        log_action("ERROR: " . $e->getMessage());
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

// Handle API request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'rotate') {
    header('Content-Type: application/json');
    $result = perform_rotation();
    echo json_encode($result);
    exit;
}

// If accessed directly via browser, show status
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    echo "Simple Rotation Script is active. Use POST request with action=rotate to trigger rotation.";
}
?>