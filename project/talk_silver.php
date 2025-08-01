<?php
// Generate a random nonce for CSP
$nonce = base64_encode(random_bytes(16));

// Add server-side security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Strict-Transport-Security: max-age=31536000;');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$nonce'; style-src 'self';");

require_once 'encrypt_json.php';

if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit();
}

$chatFile = 'temp_talk_silver.json';
$keyFile = '../private/session_key.json';

function cleanSessionKeyFile($file)
{
    $currentTime = time();
    $data = file_exists($file) ? decryptJson(file_get_contents($file)) : [];
    $performedCleanup = false;

    if (!isset($data['last_cleanup']) || ($currentTime - $data['last_cleanup']) >= 86400) {
        $data['keys'] = array_slice($data['keys'] ?? [], -288);
        $data['offset'] = $data['offset'] ?? random_int(0, 86400);
        $data['last_cleanup'] = $currentTime;
        $data['last_rotation'] = $data['last_rotation'] ?? $currentTime;
        file_put_contents($file, encryptJson($data), LOCK_EX);
        chmod($file, 0600);
        $performedCleanup = true;
        error_log("Performed cleanup on $file at " . date('Y-m-d H:i:s'));
    }

    return $performedCleanup;
}

function generateDFMimicry($sessionKeys)
{
    $latestKey = end($sessionKeys);
    $counter = time() / 300;
    return hash('sha256', $latestKey . $counter, true);
}

function loadKey($file)
{
    $currentTime = time();
    $data = file_exists($file) ? decryptJson(file_get_contents($file)) : [];
    $offset = $data['offset'] ?? random_int(0, 86400);
    $currentWindow = floor(($currentTime - $offset) / 300);
    $keys = $data['keys'] ?? [];

    $foundCurrentKey = false;
    foreach ($keys as $keyEntry) {
        if ($keyEntry['window'] == $currentWindow) {
            $realKey = $keyEntry['key'];
            $foundCurrentKey = true;
            break;
        }
    }

    if (!$foundCurrentKey) {
        $realKey = generateRealKey($offset);
        $keys[] = ['window' => $currentWindow, 'key' => $realKey];
        $keys = array_filter($keys, function ($keyEntry) use ($currentWindow) {
            return ($currentWindow - $keyEntry['window']) * 300 <= 300;
        });
        $keys = array_values($keys);
    }

    $dfKey = generateDFMimicry(array_column($keys, 'key'));
    file_put_contents($file, encryptJson([
        'offset' => $offset,
        'keys' => $keys,
        'df_key' => base64_encode($dfKey),
        'last_hour' => $data['last_hour'] ?? 0,
        'last_cleanup' => $data['last_cleanup'] ?? $currentTime,
        'last_rotation' => $data['last_rotation'] ?? $currentTime
    ]), LOCK_EX);
    chmod($file, 0600);
    error_log("Loaded key for window $currentWindow from $file");
    return $realKey;
}

function generateRealKey($offset)
{
    try {
        $timeWindow = floor((time() - $offset) / 300);
        $xBytes = openssl_random_pseudo_bytes(32);
        $x = gmp_init(bin2hex($xBytes), 16);
        error_log("Generated x: " . gmp_strval($x));

        $modulusHex = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF';
        $modulus = gmp_init($modulusHex, 16);
        error_log("Using hardcoded modulus: " . gmp_strval($modulus));

        $base = gmp_init(2, 10);
        error_log("Using base: " . gmp_strval($base));

        $maxExp = gmp_sub($modulus, gmp_init(1));
        $exp = gmp_mod($x, $maxExp);
        error_log("Using exponent: " . gmp_strval($exp));

        $result = gmp_powm($base, $exp, $modulus);
        error_log("Result: " . gmp_strval($result));

        for ($i = 0; $i < 10; $i++) {
            if (mt_rand(0, 9) === 0) {
                usleep(mt_rand(100, 1000));
            }
        }

        $randomNum = gmp_strval($result);
        $key = base64_encode(hash('sha256', $timeWindow . $randomNum, true));
        error_log("Generated key for window $timeWindow: $key");
        return $key;
    } catch (Exception $e) {
        error_log("Error generating key: " . $e->getMessage() . " at line " . $e->getLine());
        return base64_encode(hash('sha256', $timeWindow . random_bytes(16), true));
    }
}

cleanSessionKeyFile($keyFile);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');

    if ($_POST['action'] === 'get_key') {
        $key = loadKey($keyFile);
        $data = decryptJson(file_get_contents($keyFile));
        $allKeys = array_column($data['keys'], 'key');
        echo json_encode(['key' => base64_encode($key), 'all_keys' => $allKeys]);
        error_log("Sent key response: " . json_encode(['key' => base64_encode($key)]));
        exit;
    }

    if ($_POST['action'] === 'check_cleanup') {
        $performedCleanup = cleanSessionKeyFile($keyFile);
        echo json_encode(['cleanupPerformed' => $performedCleanup]);
        error_log("Cleanup check response: " . json_encode(['cleanupPerformed' => $performedCleanup]));
        exit;
    }

    if ($_POST['action'] === 'check_rotation') {
        $currentTime = time();
        $data = decryptJson(file_get_contents($keyFile));
        $lastRotation = $data['last_rotation'] ?? 0;
        $oneDay = 24 * 60 * 60;
        $needsRotation = ($currentTime - $lastRotation) >= $oneDay;
        echo json_encode(['needsRotation' => $needsRotation]);
        error_log("Rotation check response: " . json_encode(['needsRotation' => $needsRotation]));
        exit;
    }
}

function loadMessages($file)
{
    if (file_exists($file)) {
        $data = json_decode(file_get_contents($file), true);
        if ($data && isset($data['messages'])) {
            $currentTime = time();
            $messages = array_filter($data['messages'], function ($msg) use ($currentTime) {
                if (!isset($msg['timestamp'])) {
                    error_log("Message missing timestamp in loadMessages: " . json_encode($msg));
                    return false;
                }
                $timeSinceMessage = $currentTime - $msg['timestamp'];
                if ($timeSinceMessage < 300) {
                    return true;
                } else {
                    error_log("Expiring message in loadMessages: " . json_encode($msg) . " (age: $timeSinceMessage seconds)");
                    return false;
                }
            });
            return array_map(function ($msg) {
                return [
                    'content' => $msg['content'],
                    'timestamp' => $msg['timestamp']
                ];
            }, $messages);
        } else {
            error_log("Failed to load or parse messages from $file");
        }
    } else {
        error_log("Chat file $file does not exist");
    }
    return [];
}

function saveMessages($file, $messages, $timestamp)
{
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
    error_log("Received encrypted message: '$encrypted_message'");

    if (empty($encrypted_message)) {
        error_log("Empty encrypted message received");
        echo json_encode(['success' => false, 'error' => 'Empty message']);
        exit;
    }

    try {
        $data = file_exists($chatFile) ? json_decode(file_get_contents($chatFile), true) : ['messages' => []];
        if ($data === null) {
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
            $timeSinceMessage = $currentTime - $msg['timestamp'];
            if ($timeSinceMessage < 300) {
                return true;
            } else {
                error_log("Expiring message in POST handler: " . json_encode($msg) . " (age: $timeSinceMessage seconds)");
                return false;
            }
        });

        $messages = array_slice($messages, -200);
        if (!saveMessages($chatFile, $messages, $currentTime)) {
            error_log("Failed to save messages to $chatFile in POST handler");
            echo json_encode(['success' => false, 'error' => 'Failed to save message']);
            exit;
        }

        error_log("Message saved successfully: '$encrypted_message'");
        echo json_encode(['success' => true]);
    } catch (Exception $e) {
        error_log("Error in POST handler: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => 'Server error: ' . $e->getMessage()]);
    }
    exit;
}

$messages = loadMessages($chatFile);
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
            <div class="chat-box" id="chat-box">
                <div id="loading-indicator">Loading...</div>
            </div>
            <form class="chat-form" id="chat-form" onsubmit="return false;">
                <div class="form-group">
                    <input type="text" id="message-input" placeholder="Tap on the keyboard..." required>
                    <input type="hidden" name="encrypted_message" id="encrypted-message">
                </div>
                <div class="button-group">
                    <button type="submit" class="submit-btn">Send</button>
                    <button type="button" class="clear-btn" id="clear-btn">Clear</button>
                    <button type="button" class="open-btn" id="go-private-btn">Go Private</button>
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
    <script nonce="<?php echo $nonce; ?>">
        const initialMessages = <?php echo json_encode($messages); ?>;
    </script>
    <script src="silver.js"></script>
</body>

</html>
