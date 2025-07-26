<?php
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
    return $realKey;
}

function generateRealKey($offset) {
    try {
        $timeWindow = floor((time() - $offset) / 300);

        // Use openssl_random_pseudo_bytes for a secure 32-byte exponent
        $xBytes = openssl_random_pseudo_bytes(32);
        $x = gmp_init(bin2hex($xBytes), 16);
        error_log("Generated x: " . gmp_strval($x));

        // Use a hardcoded 2048-bit safe prime modulus 
        $modulusHex = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF';
        $modulus = gmp_init($modulusHex, 16);
        error_log("Using hardcoded modulus: " . gmp_strval($modulus));

        // Base for exponentiation
        $base = gmp_init(2, 10);
        error_log("Using base: " . gmp_strval($base));

        // Modular exponentiation with GMP
        $maxExp = gmp_sub($modulus, gmp_init(1));
        $exp = gmp_mod($x, $maxExp); // Ensure exponent < modulus-1
        error_log("Using exponent: " . gmp_strval($exp));

        $result = gmp_powm($base, $exp, $modulus);
        error_log("Result: " . gmp_strval($result));
        
        // Timing delays for side-channel mitigation
        for ($i = 0; $i < 10; $i++) {
            if (mt_rand(0, 9) === 0) {
                usleep(mt_rand(100, 1000)); // 0.1-1ms delay
            }
        }

        // Hash with time window for rotation compatibility
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
        exit;
    }

    if ($_POST['action'] === 'check_cleanup') {
        $performedCleanup = cleanSessionKeyFile($keyFile);
        echo json_encode(['cleanupPerformed' => $performedCleanup]);
        exit;
    }

    if ($_POST['action'] === 'check_rotation') {
        $currentTime = time();
        $data = decryptJson(file_get_contents($keyFile));
        $lastRotation = $data['last_rotation'] ?? 0;
        $oneDay = 24 * 60 * 60;
        $needsRotation = ($currentTime - $lastRotation) >= $oneDay;
        echo json_encode(['needsRotation' => $needsRotation]);
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
        }
    }
    return [];
}

function saveMessages($file, $messages, $timestamp)
{
    $messagesForStorage = array_map(function($msg) {
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
            $timeSinceMessage = $currentTime - $msg['timestamp'];
            if ($timeSinceMessage < 300) {
                return true;
            } else {
                error_log("Expiring message in POST handler: " . json_encode($msg) . " (age: $timeSinceMessage seconds)");
                return false;
            }
        });

        $messages = array_slice($messages, -200);
        $data = [
            'messages' => $messages,
            'last_activity' => $currentTime
        ];

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
            <div class="chat-box" id="chat-box">
                <div id="loading-indicator">Loading...</div>
                <?php
                echo "<script>const initialMessages = " . json_encode($messages) . ";</script>";
                ?>
            </div>
            <form class="chat-form" id="chat-form" onsubmit="return false;">
                <div class="form-group">
                    <input type="text" id="message-input" placeholder="Tap on the keyboard..." required>
                    <input type="hidden" name="encrypted_message" id="encrypted-message">
                </div>
                <div class="button-group">
                    <button type="submit" class="submit-btn">Send</button>
                    <button type="button" class="clear-btn" onclick="clearChat()">Clear</button>
                    <button type="button" class="open-btn" onclick="location.href='talk_gold.php'">Go Private</button>
                </div>
            </form>
        </div>
        <div id="consent-box" style="display: none; position: fixed; bottom: 10px; left: 10px; padding: 10px; background: #fff; border: 1px solid #ccc; width: 360px; height: 90px;">
            <p>We use local and session storage for essential chat functionality.</p>
            <button onclick="acceptConsent()">Accept</button>
            <button onclick="rejectConsent()">Reject</button>
            <span style="margin-left: 10px;"><a href="cookie_policy.php">Cookie Policy</a></span>
        </div>
    </div>

    <script>
        function acceptConsent() {
            localStorage.setItem('cookieConsent', 'true');
            document.getElementById('consent-box').style.display = 'none';
        }

        function rejectConsent() {
            alert("Chat requires local storage. Please accept or leave.");
            document.getElementById('consent-box').style.display = 'none';
            window.location.href = "about:blank";
        }

        if (!localStorage.getItem('cookieConsent')) {
            document.getElementById('consent-box').style.display = 'block';
        }

        const keyManager = (() => {
            const KEY_TTL = 60000; // 60 seconds

            // Load state from sessionStorage
            let state = JSON.parse(sessionStorage.getItem('keyManagerState')) || {
                keys: [],
                lastFetch: 0
            };

            // Save state to sessionStorage
            const saveState = () => {
                sessionStorage.setItem('keyManagerState', JSON.stringify(state));
            };

            return {
                get: async (forceFetch = false) => {
                    const now = Date.now();
                    if (forceFetch || state.keys.length === 0 || (now - state.lastFetch > KEY_TTL)) {
                        console.log("Fetching keys... Force fetch:", forceFetch);
                        const formData = new FormData();
                        formData.append('action', 'get_key');
                        try {
                            const response = await fetch(window.location.href, {
                                method: 'POST',
                                body: formData
                            });
                            if (!response.ok) {
                                console.error('Key fetch failed:', response.status);
                                throw new Error('Failed to fetch key');
                            }
                            const data = await response.json();
                            if (data.error) {
                                console.error('Server error:', data.error);
                                throw new Error(data.error);
                            }
                            const keyData = atob(data.key);
                            state.keys = data.all_keys || [keyData];
                            state.lastFetch = now;
                            saveState();
                            console.log("Keys fetched:", state.keys);
                        } catch (error) {
                            console.error("Key manager error:", error);
                            throw error;
                        }
                    }
                    return state.keys;
                },
                getCurrentKey: async () => {
                    const allKeys = await keyManager.get();
                    return allKeys[allKeys.length - 1];
                },
                forceRefresh: async () => {
                    return await keyManager.get(true);
                }
            };
        })();

        function strToArrayBuffer(str) {
            return new TextEncoder().encode(str);
        }

        function arrayBufferToStr(buffer) {
            return new TextDecoder().decode(buffer);
        }

        async function encryptMessage(text) {
            try {
                const sharedKey = await keyManager.getCurrentKey();
                console.log('Encrypting with key:', sharedKey);
                const encoder = new TextEncoder();
                const salt = crypto.getRandomValues(new Uint8Array(16));
                const keyMaterial = await crypto.subtle.importKey(
                    'raw', encoder.encode(sharedKey), { name: 'PBKDF2' },
                    false, ['deriveBits', 'deriveKey']
                );
                const derivedKey = await crypto.subtle.deriveKey(
                    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
                    keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
                );
                const iv = crypto.getRandomValues(new Uint8Array(12));
                const encrypted = await crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv }, derivedKey, encoder.encode(text)
                );
                const saltBase64 = btoa(String.fromCharCode(...salt));
                const ivBase64 = btoa(String.fromCharCode(...iv));
                const encryptedBase64 = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
                const result = `${saltBase64}:${ivBase64}:${encryptedBase64}`;
                console.log('Encrypted message:', result);
                return result;
            } catch (error) {
                console.error("Encryption error:", error);
                throw error;
            }
        }

        async function decryptMessage(encryptedStr) {
            try {
                const [saltBase64, ivBase64, encryptedBase64] = encryptedStr.split(':');
                if (!encryptedBase64) {
                    return decryptMessageLegacy(encryptedStr);
                }
                const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
                const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
                const encrypted = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
                let allKeys = await keyManager.get();
                const encoder = new TextEncoder();
                for (const sharedKey of allKeys) {
                    try {
                        console.log("Attempting decryption with key:", sharedKey);
                        const keyMaterial = await crypto.subtle.importKey(
                            'raw', encoder.encode(sharedKey), { name: 'PBKDF2' },
                            false, ['deriveBits', 'deriveKey']
                        );
                        const derivedKey = await crypto.subtle.deriveKey(
                            { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
                            keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
                        );
                        const decrypted = await crypto.subtle.decrypt(
                            { name: 'AES-GCM', iv }, derivedKey, encrypted
                        );
                        const result = arrayBufferToStr(decrypted);
                        console.log("Decryption successful:", result);
                        return result;
                    } catch (error) {
                        console.warn("Decryption attempt failed with key:", sharedKey, "Error:", error.message);
                        continue;
                    }
                }
                // If decryption fails, force a key refresh and try again
                console.log("Decryption failed with current keys, forcing key refresh...");
                allKeys = await keyManager.forceRefresh();
                for (const sharedKey of allKeys) {
                    try {
                        console.log("Retrying decryption with refreshed key:", sharedKey);
                        const keyMaterial = await crypto.subtle.importKey(
                            'raw', encoder.encode(sharedKey), { name: 'PBKDF2' },
                            false, ['deriveBits', 'deriveKey']
                        );
                        const derivedKey = await crypto.subtle.deriveKey(
                            { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
                            keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
                        );
                        const decrypted = await crypto.subtle.decrypt(
                            { name: 'AES-GCM', iv }, derivedKey, encrypted
                        );
                        const result = arrayBufferToStr(decrypted);
                        console.log("Decryption successful after refresh:", result);
                        return result;
                    } catch (error) {
                        console.warn("Retry decryption attempt failed with key:", sharedKey, "Error:", error.message);
                        continue;
                    }
                }
                console.warn("Could not decrypt message with any available key:", encryptedStr);
                return "[Failed to decrypt]";
            } catch (error) {
                console.error("Decryption error:", error, "for:", encryptedStr);
                return "[Failed to decrypt]";
            }
        }

        async function decryptMessageLegacy(encryptedStr) {
            try {
                const [ivBase64, encryptedBase64] = encryptedStr.split(':');
                const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
                const encrypted = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
                let allKeys = await keyManager.get();
                for (const sharedKey of allKeys) {
                    try {
                        console.log("Attempting legacy decryption with key:", sharedKey);
                        const rawKey = Uint8Array.from(atob(sharedKey), c => c.charCodeAt(0));
                        const key = await crypto.subtle.importKey(
                            'raw', rawKey, { name: 'AES-CBC' }, false, ['decrypt']
                        );
                        const decrypted = await crypto.subtle.decrypt(
                            { name: 'AES-CBC', iv }, key, encrypted
                        );
                        const result = arrayBufferToStr(decrypted);
                        console.log("Legacy decryption successful:", result);
                        return result;
                    } catch (error) {
                        console.warn("Legacy decryption attempt failed with key:", sharedKey, "Error:", error.message);
                        continue;
                    }
                }
                // Force a key refresh and retry
                console.log("Legacy decryption failed with current keys, forcing key refresh...");
                allKeys = await keyManager.forceRefresh();
                for (const sharedKey of allKeys) {
                    try {
                        console.log("Retrying legacy decryption with refreshed key:", sharedKey);
                        const rawKey = Uint8Array.from(atob(sharedKey), c => c.charCodeAt(0));
                        const key = await crypto.subtle.importKey(
                            'raw', rawKey, { name: 'AES-CBC' }, false, ['decrypt']
                        );
                        const decrypted = await crypto.subtle.decrypt(
                            { name: 'AES-CBC', iv }, key, encrypted
                        );
                        const result = arrayBufferToStr(decrypted);
                        console.log("Legacy decryption successful after refresh:", result);
                        return result;
                    } catch (error) {
                        console.warn("Retry legacy decryption attempt failed with key:", sharedKey, "Error:", error.message);
                        continue;
                    }
                }
                console.warn("Could not decrypt legacy message with any available key:", encryptedStr);
                return "[Failed to decrypt]";
            } catch (error) {
                console.error("Legacy decryption error:", error, "for:", encryptedStr);
                return "[Failed to decrypt]";
            }
        }

        let isFetchingMessages = false;
        let lastMessageFetch = 0;
        const messageExpirationTimes = new Map();
        let lastMessageTimestamp = 0; // Track the latest message timestamp

        async function renderMessages(messages, chatBox) {
            console.log('Rendering messages:', messages);
            const isNearBottom = chatBox.scrollTop + chatBox.clientHeight >= chatBox.scrollHeight - 50;
            chatBox.innerHTML = '';

            if (messages.length === 0) {
                chatBox.innerHTML = '<div class="no-messages">No messages to display.</div>';
                return;
            }

            messages.sort((a, b) => a.timestamp - b.timestamp);
            messages.forEach(msg => {
                const msgDiv = document.createElement('div');
                msgDiv.className = 'message';
                msgDiv.textContent = msg.decrypted;
                msgDiv.dataset.enc = msg.encrypted;
                const expirationTime = (parseInt(msg.timestamp, 10) + 300) * 1000;
                messageExpirationTimes.set(msg.encrypted, expirationTime);
                chatBox.appendChild(msgDiv);
                lastMessageTimestamp = Math.max(lastMessageTimestamp, msg.timestamp);
            });

            if (isNearBottom) {
                chatBox.scrollTop = chatBox.scrollHeight;
            }
            console.log('Messages rendered. Total messages:', messages.length);
        }

        function checkMessageExpirations() {
            const chatBox = document.getElementById('chat-box');
            if (!chatBox) return;
            
            const now = Date.now();
            const messages = chatBox.querySelectorAll('.message');
            
            messages.forEach(msgDiv => {
                const encryptedContent = msgDiv.dataset.enc;
                const expirationTime = messageExpirationTimes.get(encryptedContent);
                
                if (expirationTime && now >= expirationTime) {
                    msgDiv.remove();
                    messageExpirationTimes.delete(encryptedContent);
                }
            });

            if (chatBox.children.length === 0) {
                chatBox.innerHTML = '<div class="no-messages">No messages to display.</div>';
            }
        }

        async function fetchMessages() {
            if (isFetchingMessages) {
                console.log('Already fetching messages, skipping...');
                return;
            }
            const now = Date.now();
            if (now - lastMessageFetch < 500) {
                console.log('Too soon to fetch messages, last fetch:', lastMessageFetch);
                return;
            }
            lastMessageFetch = now;
            isFetchingMessages = true;

            try {
                console.log('Fetching messages from fetch_messages_silver.php...');
                const response = await fetch('fetch_messages_silver.php?_=' + new Date().getTime(), {
                    cache: 'no-store',
                    headers: { 'Cache-Control': 'no-cache' }
                });
                if (!response.ok) {
                    console.error('Failed to fetch messages, status:', response.status);
                    return;
                }
                const data = await response.json();
                console.log('Fetched messages:', data);
                const encryptedMessages = Array.isArray(data) ? data : (data.messages || []);
                const chatBox = document.getElementById('chat-box');
                if (!chatBox) {
                    console.error('Chat box element not found');
                    return;
                }

                const existingMessages = new Set(
                    Array.from(chatBox.querySelectorAll('.message')).map(msgDiv => msgDiv.dataset.enc)
                );
                console.log('Existing messages:', existingMessages);

                const newMessages = [];
                const nowSeconds = Math.floor(now / 1000);
                for (const msg of encryptedMessages) {
                    if (!msg.content || !msg.timestamp) {
                        console.log('Skipping invalid message:', msg);
                        continue;
                    }
                    const timeSinceMessage = nowSeconds - msg.timestamp;
                    if (timeSinceMessage >= 300) {
                        console.log('Message expired:', msg);
                        continue;
                    }
                    if (msg.timestamp <= lastMessageTimestamp) {
                        console.log('Message already processed:', msg);
                        continue;
                    }
                    if (existingMessages.has(msg.content)) {
                        console.log('Message already exists:', msg.content);
                        continue;
                    }
                    const dec = await decryptMessage(msg.content);
                    console.log('Decrypted message:', dec);
                    newMessages.push({ decrypted: dec, encrypted: msg.content, timestamp: msg.timestamp });
                }

                console.log('New messages to render:', newMessages);
                const isNearBottom = chatBox.scrollTop + chatBox.clientHeight >= chatBox.scrollHeight - 50;
                newMessages.sort((a, b) => a.timestamp - b.timestamp);
                newMessages.forEach(msg => {
                    const msgDiv = document.createElement('div');
                    msgDiv.className = 'message';
                    msgDiv.textContent = msg.decrypted;
                    msgDiv.dataset.enc = msg.encrypted;
                    const expirationTime = (parseInt(msg.timestamp, 10) + 300) * 1000;
                    messageExpirationTimes.set(msg.encrypted, expirationTime);
                    chatBox.appendChild(msgDiv);
                    lastMessageTimestamp = Math.max(lastMessageTimestamp, msg.timestamp);
                });

                if (isNearBottom && newMessages.length > 0) {
                    chatBox.scrollTop = chatBox.scrollHeight;
                }

                if (chatBox.children.length === 0) {
                    chatBox.innerHTML = '<div class="no-messages">No messages to display.</div>';
                }
            } catch (error) {
                console.error('Error in fetchMessages:', error.message);
            } finally {
                isFetchingMessages = false;
            }
        }

        async function loadInitialMessages() {
            const loadingIndicator = document.getElementById('loading-indicator');
            if (loadingIndicator) loadingIndicator.textContent = "Decrypting messages...";
            const chatBox = document.getElementById('chat-box');
            if (!chatBox) {
                console.error('Chat box element not found during initial load');
                return;
            }

            console.log('Initial messages:', initialMessages);
            const decryptedMessages = await Promise.all(
                initialMessages.map(async msg => {
                    if (!msg.content || !msg.timestamp) {
                        console.log('Skipping invalid initial message:', msg);
                        return null;
                    }
                    const dec = await decryptMessage(msg.content);
                    console.log('Initial message decrypted:', dec);
                    return { decrypted: dec, encrypted: msg.content, timestamp: msg.timestamp };
                })
            );

            const validMessages = decryptedMessages.filter(msg => msg !== null);
            console.log('Valid initial messages:', validMessages);
            await renderMessages(validMessages, chatBox);

            if (loadingIndicator) loadingIndicator.remove();

            setInterval(fetchMessages, 1000);
            setInterval(checkMessageExpirations, 1000);
            setInterval(simpleKeyRotation, 60000);
        }

        function clearChat() {
            document.getElementById('message-input').value = '';
        }

        async function simpleKeyRotation() {
            try {
                const formData = new FormData();
                formData.append('action', 'check_rotation');
                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    console.error('Rotation check failed:', response.status);
                    return;
                }

                const data = await response.json();
                if (data.needsRotation) {
                    console.log("Rotation needed, triggering rotation...");
                    const rotateFormData = new FormData();
                    rotateFormData.append('action', 'rotate');
                    const rotateResponse = await fetch('simple_rotation.php', {
                        method: 'POST',
                        body: rotateFormData
                    });

                    if (!rotateResponse.ok) {
                        console.error('Rotation failed:', rotateResponse.status);
                        return;
                    }

                    const rotateData = await rotateResponse.json();
                    if (rotateData.success) {
                        await keyManager.forceRefresh();
                        console.log('Keys refreshed after rotation');
                    } else {
                        console.error('Rotation failed:', rotateData.error);
                    }
                } else {
                    console.log("No rotation needed.");
                }
            } catch (error) {
                console.error('Rotation check error:', error.message);
            }
        }

        function handleFormSubmit(e) {
            e.preventDefault();
            e.stopPropagation();

            const messageInput = document.getElementById('message-input');
            const message = messageInput.value.trim();

            if (!message) return;

            (async () => {
                try {
                    const encrypted = await encryptMessage(message);
                    console.log('Message encrypted:', encrypted);
                    document.getElementById('encrypted-message').value = encrypted;

                    const formData = new FormData();
                    formData.append('encrypted_message', encrypted);
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        body: formData
                    });

                    if (!response.ok) {
                        console.error('Message send failed:', response.status, response.statusText);
                        throw new Error('Failed to send message: HTTP ' + response.status);
                    }

                    const data = await response.json();
                    if (!data.success) {
                        console.error('Server rejected message:', data);
                        throw new Error('Server rejected message: ' + (data.error || 'Unknown error'));
                    }

                    messageInput.value = '';
                    document.getElementById('encrypted-message').value = '';

                    setTimeout(fetchMessages, 500);
                } catch (error) {
                    console.error("Error sending message:", error.message || error);
                    alert("Failed to send message: " + (error.message || "Unknown error") + ". Please try again.");
                }
            })();
        }

        document.addEventListener('DOMContentLoaded', () => {
            const chatForm = document.getElementById('chat-form');
            if (!chatForm) {
                console.error("Chat form not found");
                return;
            }

            chatForm.addEventListener('submit', handleFormSubmit);

            (async () => {
                try {
                    await loadInitialMessages();
                } catch (error) {
                    console.error("Error initializing chat:", error);
                    const loadingIndicator = document.getElementById('loading-indicator');
                    if (loadingIndicator) loadingIndicator.textContent = "Error loading chat. Please refresh.";
                }
            })();
        });
    </script>
</body>
</html>