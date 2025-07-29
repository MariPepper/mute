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