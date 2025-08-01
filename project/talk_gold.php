<?php
// Generate a random nonce for CSP
$nonce = base64_encode(random_bytes(16));

// Security Headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Strict-Transport-Security: max-age=31536000;');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$nonce'; style-src 'self';");

if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit();
}

require_once 'encrypt_json.php';

$chatFile = 'temp_talk_gold.json';

function loadMessages($file) {
    if (file_exists($file)) {
        $data = json_decode(file_get_contents($file), true);
        if ($data && isset($data['messages'])) {
            $currentTime = time();
            $messages = array_filter($data['messages'], function ($msg) use ($currentTime) {
                if (!isset($msg['timestamp'])) {
                    error_log("Message missing timestamp in loadMessages: " . json_encode($msg));
                    return false;
                }
                return ($currentTime - $msg['timestamp']) < 300;
            });
            return array_map(function ($msg) {
                return $msg['content'];
            }, $messages);
        }
    }
    return [];
}

function saveMessages($file, $messages, $timestamp) {
    $messagesForStorage = array_map(function ($msg) {
        return [
            'content' => $msg['content'],
            'timestamp' => $msg['timestamp']
        ];
    }, $messages);

    $messagesForStorage = array_slice($messagesForStorage, -200);
    $data = [
        'messages' => $messagesForStorage,
        'last_activity' => $timestamp
    ];

    if (!file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX)) {
        error_log("Failed to write messages to $file");
        return false;
    }
    chmod($file, 0600);
    error_log("Saved messages: " . count($messagesForStorage) . " at " . date('Y-m-d H:i:s', $timestamp));
    return true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['encrypted_message'])) {
    header('Content-Type: application/json');
    $encrypted_message = trim($_POST['encrypted_message']);

    if (empty($encrypted_message)) {
        error_log("Empty encrypted message received");
        echo json_encode(['success' => false, 'error' => 'Empty message']);
        exit;
    }

    try {
        $data = file_exists($chatFile) ? json_decode(file_get_contents($chatFile), true) : ['messages' => []];
        if (!$data) {
            error_log("Failed to decode JSON from $chatFile");
            echo json_encode(['success' => false, 'error' => 'Failed to load chat data']);
            exit;
        }

        $messages = $data['messages'] ?? [];
        $currentTime = time();
        $messages[] = [
            'content' => $encrypted_message,
            'timestamp' => $currentTime
        ];

        $messages = array_filter($messages, function ($msg) use ($currentTime) {
            if (!isset($msg['timestamp'])) {
                error_log("Message missing timestamp in POST handler: " . json_encode($msg));
                return false;
            }
            return ($currentTime - $msg['timestamp']) < 300;
        });

        $messages = array_slice($messages, -200);
        if (!saveMessages($chatFile, $messages, $currentTime)) {
            error_log("Failed to save messages to $chatFile in POST handler");
            echo json_encode(['success' => false, 'error' => 'Failed to save message']);
            exit;
        }

        echo json_encode(['success' => true]);
    } catch (Exception $e) {
        error_log("Error in POST handler: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => 'Server error: ' . $e->getMessage()]);
    }
    exit;
}

$messages = loadMessages($chatFile);
$serverTime = time();
?>
<!DOCTYPE html>
<html lang="en-US">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multi-User Encrypted Timed Chat</title>
    <link rel="stylesheet" type="text/css" href="style-7.css">
</head>

<body>
    <div class="container">
        <div class="header">Multi-User Timed Encrypted Chat <sup>MUTE</sup></div>
        <div class="content">
            <div id="key-entry">
                <label for="chat-key-input">Enter the chat key (shared offline):</label>
                <input type="password" id="chat-key-input" minlength="16" required>
                <button type="button" id="submit-key-btn">Submit Key</button>
            </div>
            <div class="chat-box" id="chat-box"></div>
            <form method="POST" action="" class="chat-form" id="chat-form">
                <div class="form-group">
                    <input type="text" id="message-input" placeholder="Tap on the keyboard..." required>
                    <input type="hidden" name="encrypted_message" id="encrypted-message">
                </div>
                <div class="button-group">
                    <button type="submit" class="submit-btn">Send</button>
                    <button type="button" class="clear-btn" id="clear-btn">Clear</button>
                    <button type="button" class="reset-btn" id="reset-key-btn">Reset Key</button>
                    <button type="button" class="open-btn" id="go-public-btn">Go Public</button>
                </div>
            </form>
            <div id="consent-box">
                <p>We use local and session storage for essential chat functionality.</p>
                <button id="accept-consent">Accept</button>
                <button id="reject-consent">Reject</button>
                <span class="consent-link">
                    <a href="cookie_policy.html">Cookie Policy</a>
                </span>
            </div>
        </div>
    </div>
    <!-- Pass PHP data to JavaScript -->
    <script nonce="<?php echo $nonce; ?>">
        const serverMessages = <?php echo json_encode($messages); ?>;
        const serverTime = <?php echo time(); ?>;
    </script>

    <!-- Load external JavaScript file -->
    <script src="gold.js" nonce="<?php echo $nonce; ?>"></script>
</body>

</html>
