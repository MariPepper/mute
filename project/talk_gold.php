                <?php
                // Security Headers
                header('X-Content-Type-Options: nosniff');
                header('X-Frame-Options: DENY');
                header('X-XSS-Protection: 1; mode=block');
                header('Referrer-Policy: strict-origin-when-cross-origin');
                header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
                header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'');

                require_once 'encrypt_json.php'; // For encryptJson and decryptJson

                // Force HTTPS
                if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
                    header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
                    exit();
                }

                $chatFile = 'temp_talk_gold.json';
                $saltFile = '../private/salt_key_mapping.json'; // File to store salt-key mappings

                // Security logging function
                function secureLog($message, $level = 'INFO')
                {
                    $logFile = '../private/chat_security.log';
                    $timestamp = date('Y-m-d H:i:s');
                    $entry = "[$timestamp] [$level] $message" . PHP_EOL;
                    file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
                }

                // Input validation function
                function validateEncryptedMessage($message)
                {
                    if (!preg_match('/^[A-Za-z0-9+\/=]+:[A-Za-z0-9+\/=]+:[0-9]+$/', $message)) {
                        return false;
                    }

                    if (strlen($message) > 10000) {
                        return false;
                    }

                    $parts = explode(':', $message);
                    $timestamp = intval($parts[2]);
                    $currentTime = time() * 1000;
                    if ($timestamp < ($currentTime - 3600000) || $timestamp > ($currentTime + 300000)) {
                        return false;
                    }

                    return true;
                }

                function loadMessages($file)
                {
                    if (file_exists($file)) {
                        $data = json_decode(file_get_contents($file), true);
                        if ($data && isset($data['messages'])) {
                            $currentTime = time();
                            if (!isset($data['last_cleanup']) || ($currentTime - $data['last_cleanup']) > 60) {
                                $validMessages = array_filter($data['messages'], function ($message) use ($currentTime) {
                                    if (is_string($message)) {
                                        return true; // Keep legacy messages for migration
                                    }
                                    return isset($message['timestamp']) && ($currentTime - $message['timestamp']) < 300; // 5 minutes
                                });
                                $validMessages = array_values($validMessages);
                                if (count($validMessages) !== count($data['messages'])) {
                                    $expiredCount = count($data['messages']) - count($validMessages);
                                    secureLog("Cleaned $expiredCount expired messages");
                                    saveMessages($file, $validMessages, $currentTime);
                                }
                                return $validMessages;
                            }
                            return $data['messages'];
                        }
                    }
                    return [];
                }

                function saveMessages($file, $messages, $timestamp)
                {
                    $data = ['messages' => $messages, 'last_activity' => $timestamp, 'last_cleanup' => $timestamp];
                    file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
                    chmod($file, 0600);
                }

                // Function to manage salt-key mapping
                function getSaltForKey($key, $saltFile)
                {
                    $keyHash = hash('sha256', $key);
                    $data = file_exists($saltFile) ? decryptJson(file_get_contents($saltFile)) : [];
                    if (!isset($data[$keyHash])) {
                        $salt = base64_encode(random_bytes(16)); // 16-byte random salt
                        $data[$keyHash] = $salt;
                        file_put_contents($saltFile, encryptJson($data), LOCK_EX);
                        chmod($saltFile, 0600);
                        secureLog("New salt generated for key hash: $keyHash");
                    }
                    return base64_decode($data[$keyHash]);
                }

                if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['encrypted_message'])) {
                    $encrypted_message = trim($_POST['encrypted_message']);

                    if (empty($encrypted_message)) {
                        secureLog("Empty message submitted", 'WARNING');
                        http_response_code(400);
                        exit('Empty message');
                    }

                    if (!validateEncryptedMessage($encrypted_message)) {
                        secureLog("Invalid message format submitted", 'WARNING');
                        http_response_code(400);
                        exit('Invalid message format');
                    }

                    $messages = loadMessages($chatFile);
                    $messageObj = [
                        'content' => $encrypted_message,
                        'timestamp' => time(),
                    ];
                    $messages[] = $messageObj;
                    saveMessages($chatFile, $messages, time());

                    secureLog("Message posted successfully");
                    header("Location: " . $_SERVER['PHP_SELF']);
                    exit();
                }

                $messages = loadMessages($chatFile);
                $messageContents = array_map(function ($msg) {
                    return is_array($msg) ? $msg['content'] : $msg;
                }, $messages);
                echo "<script>const serverMessages = " . json_encode($messageContents) . "; const serverTime = " . time() . ";</script>";
                ?>
                <!DOCTYPE html>
                <html lang="en-US">

                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Multi-User Encrypted Timed Chat</title>
                    <link rel="stylesheet" type="text/css" href="style-6.css">
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
                                    <input type="text" id="message-input" placeholder="Tap on the keyboard..." required maxlength="1000">
                                    <input type="hidden" name="encrypted_message" id="encrypted-message">
                                </div>
                                <div class="button-group">
                                    <button type="submit" class="submit-btn">Send</button>
                                    <button type="button" class="clear-btn" id="clear-btn">Clear</button>
                                    <button type="button" class="reset-btn" id="reset-key-btn">Reset Key</button>
                                    <button type="button" class="open-btn" id="go-public-btn">Go Public</button>
                                </div>
                            </form>
                        </div>
                        <div id="consent-box">
                            <p>We use session storage for essential chat functionality.</p>
                            <button id="accept-consent">Accept</button>
                            <button id="reject-consent">Reject</button>
                            <span class="consent-link">
                                <a href="cookie_policy.html">Cookie Policy</a>
                            </span>
                        </div>
                    </div>

                    <!-- Pass PHP data to JavaScript -->
                    <script>
                        const serverMessages = <?php echo json_encode($messageContents); ?>;
                        const serverTime = <?php echo time(); ?>;
                    </script>

                    <!-- Load external JavaScript file -->
                    <script src="gold.js"></script>
                </body>

                </html>
