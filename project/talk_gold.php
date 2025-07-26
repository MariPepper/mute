<!DOCTYPE html><html lang="en-US">
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
            <div id="key-entry" style="display: block; margin-bottom: 10px;">
                <label for="chat-key-input">Enter the chat key (shared offline):</label>
                <input type="password" id="chat-key-input" minlength="16" required>
                <button type="button" onclick="submitKey()">Submit Key</button>
            </div>
            <div class="chat-box" id="chat-box">
                <?php
                // Security Headers
                header('X-Content-Type-Options: nosniff');
                header('X-Frame-Options: DENY');
                header('X-XSS-Protection: 1; mode=block');
                header('Referrer-Policy: strict-origin-when-cross-origin');
                header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'');

            require_once 'encrypt_json.php'; // For encryptJson and decryptJson

            // Force HTTPS
            if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
                header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
                exit();
            }

            $chatFile = 'temp_talk_gold.json';
            $saltFile = 'salt_key_mapping.json'; // File to store salt-key mappings

            // Security logging function
            function secureLog($message, $level = 'INFO')
            {
                $logFile = '../private/chat_security.log';
                $timestamp = date('Y-m-d H:i:s');
                $clientIP = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'];
                $entry = "[$timestamp] [$level] [$clientIP] $message" . PHP_EOL;
                file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
            }

            // Rate limiting function
            function checkRateLimit($identifier, $maxRequests = 10, $timeWindow = 60)
            {
                $rateLimitDir = 'rate_limits/';
                if (!file_exists($rateLimitDir)) {
                    mkdir($rateLimitDir, 0700, true);
                }

                $rateLimitFile = $rateLimitDir . "rate_limit_" . hash('sha256', $identifier) . ".json";
                $currentTime = time();

                if (file_exists($rateLimitFile)) {
                    $data = json_decode(file_get_contents($rateLimitFile), true) ?: [];
                    $requests = array_filter($data, function ($timestamp) use ($currentTime, $timeWindow) {
                        return ($currentTime - $timestamp) < $timeWindow;
                    });

                    if (count($requests) >= $maxRequests) {
                        return false;
                    }

                    $requests[] = $currentTime;
                } else {
                    $requests = [$currentTime];
                }

                file_put_contents($rateLimitFile, json_encode($requests), LOCK_EX);
                chmod($rateLimitFile, 0600);
                return true;
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
        </div>
        <form method="POST" action="" class="chat-form" id="chat-form">
            <div class="form-group">
                <input type="text" id="message-input" placeholder="Tap on the keyboard..." required maxlength="1000">
                <input type="hidden" name="encrypted_message" id="encrypted-message">
            </div>
            <div class="button-group">
                <button type="submit" class="submit-btn">Send</button>
                <button type="button" class="clear-btn" onclick="clearChat()">Clear</button>
                <button type="button" class="reset-btn" onclick="resetChatKey()">Reset Key</button>
                <button type="button" class="open-btn" onclick="location.href='talk_silver.php'">Go Public</button>
            </div>
        </form>
    </div>
    <div id="consent-box" style="display: none; position: fixed; bottom: 10px; left: 10px; padding: 10px; background: #fff; border: 1px solid #ccc; width: 360px; height: 90px;">
        <p>We use session storage for essential chat functionality.</p>
        <button onclick="acceptConsent()">Accept</button>
        <button onclick="rejectConsent()">Reject</button>
        <span style="margin-left: 10px;">
            <a href="cookie_policy.php">Cookie Policy</a>
        </span>
    </div>
</div>

<script>
    // Security: Clear sensitive data on page unload
    let SHARED_KEY = null;
    let derivedKey = null;
    let lastActivity = Date.now();

    // Function to fetch salt from server
    async function getSaltForKey(key) {
        const keyHash = await hashKey(key);
        const response = await fetch('get_salt.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `key_hash=${encodeURIComponent(keyHash)}`
        });
        if (!response.ok) throw new Error('Failed to fetch salt');
        const data = await response.json();
        return base64ToUint8Array(data.salt);
    }

    function base64ToUint8Array(base64) {
        const binaryString = atob(base64);
        return Uint8Array.from(binaryString, c => c.charCodeAt(0));
    }

    async function hashKey(key) {
        const encoder = new TextEncoder();
        const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(key));
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Fixed key derivation with salt per key from server
    async function deriveKey(password) {
        try {
            const salt = await getSaltForKey(password);
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(password),
                'PBKDF2',
                false,
                ['deriveBits', 'deriveKey']
            );
            
            return crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 100000,
                    hash: 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
        } catch (error) {
            console.error("Key derivation error:", error);
            throw error;
        }
    }

    async function submitKey() {
        const keyInput = document.getElementById('chat-key-input').value;
        if (!keyInput || keyInput.length < 16) {
            alert('Key must be at least 16 characters!');
            return;
        }
        
        try {
            SHARED_KEY = keyInput;
            derivedKey = await deriveKey(SHARED_KEY);
            sessionStorage.setItem('chatKey', SHARED_KEY);
            
            document.getElementById('key-entry').style.display = 'none';
            document.getElementById('chat-form').style.display = 'block';
            
            await initializeChat();
        } catch (error) {
            console.error("Error setting up key:", error);
            alert("Error setting up encryption key. Please try again.");
        }
    }

    // Initialize from session storage
    (async function() {
        SHARED_KEY = sessionStorage.getItem('chatKey');
        if (SHARED_KEY) {
            try {
                derivedKey = await deriveKey(SHARED_KEY);
                document.getElementById('key-entry').style.display = 'none';
                document.getElementById('chat-form').style.display = 'block';
                await initializeChat();
            } catch (error) {
                console.error("Error initializing from stored key:", error);
                resetChatKey();
            }
        } else {
            document.getElementById('chat-form').style.display = 'none';
        }
    })();

    function resetChatKey() {
        sessionStorage.removeItem('chatKey');
        sessionStorage.removeItem('chatMessages');
        SHARED_KEY = null;
        derivedKey = null;
        location.reload();
    }

    // Input sanitization
    function sanitizeInput(input) {
        return input.replace(/[<>\"'&]/g, '').trim();
    }

    // Enhanced encryption with timestamp and integrity
    async function encryptMessage(text) {
        try {
            if (!derivedKey) throw new Error("Key not derived");
            
            const timestamp = Date.now().toString();
            const payload = JSON.stringify({ message: text, timestamp: parseInt(timestamp) });
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            const encrypted = await crypto.subtle.encrypt(
                { 
                    name: 'AES-GCM', 
                    iv: iv,
                    additionalData: new TextEncoder().encode(timestamp)
                },
                derivedKey,
                new TextEncoder().encode(payload)
            );
            
            return `${btoa(String.fromCharCode(...iv))}:${btoa(String.fromCharCode(...new Uint8Array(encrypted)))}:${timestamp}`;
        } catch (error) {
            console.error("Encryption error:", error);
            throw error;
        }
    }

    async function decryptMessage(encryptedStr) {
        try {
            if (!derivedKey) throw new Error("Key not derived");
            
            const parts = encryptedStr.split(':');
            if (parts.length !== 3) throw new Error("Invalid encrypted message format");
            
            const [ivBase64, encryptedBase64, timestamp] = parts;
            const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
            const encrypted = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
            
            const decrypted = await crypto.subtle.decrypt(
                { 
                    name: 'AES-GCM', 
                    iv: iv,
                    additionalData: new TextEncoder().encode(timestamp)
                },
                derivedKey,
                encrypted
            );
            
            const payload = JSON.parse(new TextDecoder().decode(decrypted));
            return payload.message;
        } catch (error) {
            console.error("Decryption error:", error);
            return null;
        }
    }

    let localMessages = JSON.parse(sessionStorage.getItem('chatMessages')) || [];
    const chatBox = document.getElementById('chat-box');
    const chatForm = document.getElementById('chat-form');
    const msgInput = document.getElementById('message-input');

    function displayMessages(messages, referenceTime) {
        chatBox.innerHTML = '';
        const currentTime = referenceTime || Date.now();
        const validMessages = messages.filter(msgObj => {
            if (typeof msgObj === 'string') return true; // Keep legacy messages
            const messageAge = currentTime - msgObj.timestamp;
            const isExpired = messageAge > 300000; // 5 minutes
            return !isExpired;
        });

        if (validMessages.length !== messages.length) {
            localMessages = validMessages;
            saveLocalMessages(localMessages);
        }

        validMessages.forEach(msgObj => {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message';
            const messageText = typeof msgObj === 'string' ? msgObj : msgObj.content;
            messageDiv.innerHTML = `<span class="message-text">${escapeHtml(messageText)}</span>`;
            chatBox.appendChild(messageDiv);
        });
        chatBox.scrollTop = chatBox.scrollHeight;
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function saveLocalMessages(messages) {
        sessionStorage.setItem('chatMessages', JSON.stringify(messages));
    }

    async function fetchMessages() {
        if (!derivedKey) return;
        
        try {
            const response = await fetch('fetch_messages_gold.php');
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();
            const serverTimeMs = data.server_time * 1000;
            
            const decryptedMessages = await Promise.all(
                data.messages.map(async (msg, index) => {
                    const encContent = typeof msg === 'object' && msg.content ? msg.content : msg;
                    const decrypted = await decryptMessage(encContent);
                    if (decrypted !== null) {
                        const timestamp = typeof msg === 'object' && msg.timestamp ?
                            msg.timestamp * 1000 : serverTimeMs - (index * 1000);
                        return { content: decrypted, timestamp };
                    }
                    return null;
                })
            );
            
            const validMessages = decryptedMessages.filter(msg => msg !== null);
            
            if (JSON.stringify(localMessages.map(m => m.content)) !== JSON.stringify(validMessages.map(m => m.content)) || validMessages.length !== localMessages.length) {
                localMessages = validMessages;
                saveLocalMessages(localMessages);
                displayMessages(localMessages, serverTimeMs);
            }
        } catch (error) {
            console.error("Error fetching messages:", error);
        }
    }

    async function initializeChat() {
        try {
            if (typeof serverMessages !== 'undefined' && serverMessages.length > 0) {
                const decryptedServerMessages = await Promise.all(
                    serverMessages.map(async (enc, index) => {
                        const decrypted = await decryptMessage(enc);
                        if (decrypted !== null) {
                            return {
                                content: decrypted,
                                timestamp: serverTime * 1000 - (index * 1000)
                            };
                        }
                        return null;
                    })
                );
                localMessages = decryptedServerMessages.filter(msg => msg !== null);
                saveLocalMessages(localMessages);
                displayMessages(localMessages, serverTime * 1000);
            }
            
            // Start periodic updates
            setInterval(fetchMessages, 2000);
            
            // Periodic cleanup
            setInterval(() => {
                displayMessages(localMessages);
            }, 60000);
            
        } catch (error) {
            console.error("Error initializing chat:", error);
        }
    }

    chatForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!derivedKey) {
            alert("Encryption key not ready. Please wait or reset the key.");
            return;
        }
        
        let message = sanitizeInput(msgInput.value);
        if (message && message.length > 0) {
            // Client-side length validation
            if (message.length > 1000) {
                alert('Message too long (max 1000 characters)');
                return;
            }
            
            try {
                const encrypted = await encryptMessage(message);
                const timestamp = Date.now();
                
                // Add to local messages immediately for responsiveness
                localMessages.push({ content: message, timestamp });
                displayMessages(localMessages);
                saveLocalMessages(localMessages);
                
                // Send to server
                const formData = new FormData();
                formData.append('encrypted_message', encrypted);
                
                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                msgInput.value = '';
                lastActivity = Date.now(); // Update activity timestamp
                
            } catch (error) {
                console.error("Error sending message:", error);
                alert("Failed to send message. Please try again.");
                // Remove the optimistically added message
                localMessages.pop();
                displayMessages(localMessages);
                saveLocalMessages(localMessages);
            }
        }
    });

    function clearChat() {
        msgInput.value = '';
    }

    // Session timeout management
    setInterval(() => {
        console.log("Periodic timeout check at", new Date().toLocaleTimeString());
        if (Date.now() - lastActivity > 30 * 60 * 1000) { // 30 minutes
            resetChatKey();
            alert('Session expired due to inactivity');
        }
    }, 60000);

    // Update activity on user interaction
    document.addEventListener('click', () => lastActivity = Date.now());
    document.addEventListener('keypress', () => lastActivity = Date.now());
    msgInput.addEventListener('input', () => lastActivity = Date.now());
</script></body>
</html>

