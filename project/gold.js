let SHARED_KEY = null;
let derivedKey = null;
let lastActivity = Date.now();

function acceptConsent() {
    sessionStorage.setItem('cookieConsent', 'true');
    document.getElementById('consent-box').style.display = 'none';
}

function rejectConsent() {
    alert("Chat requires session storage. Please accept or leave.");
    document.getElementById('consent-box').style.display = 'none';
    window.location.href = "about:blank";
}

if (!sessionStorage.getItem('cookieConsent')) {
    document.getElementById('consent-box').style.display = 'block';
}

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

async function initializeFromStorage() {
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
}

function resetChatKey() {
    sessionStorage.removeItem('chatKey');
    sessionStorage.removeItem('chatMessages');
    SHARED_KEY = null;
    derivedKey = null;
    location.reload();
}

function sanitizeInput(input) {
    return input.replace(/[<>\"'&]/g, '').trim();
}

async function encryptMessage(text) {
    try {
        if (!derivedKey) throw new Error("Key not derived");
        
        const displayName = sessionStorage.getItem('displayName') || 'Anonymous';
        const timestamp = Date.now();
        if (Math.abs(timestamp - Date.now()) > 300000) {
            throw new Error("Client clock is too far off; please sync time");
        }
        const payload = JSON.stringify({ 
            name: displayName, 
            message: text, 
            timestamp: timestamp 
        });
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        const encrypted = await crypto.subtle.encrypt(
            { 
                name: 'AES-GCM', 
                iv: iv,
                additionalData: new TextEncoder().encode(timestamp.toString())
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
        return { name: payload.name || 'Anonymous', message: payload.message };
    } catch (error) {
        console.error("Decryption error:", error);
        return null;
    }
}

let localMessages = JSON.parse(sessionStorage.getItem('chatMessages')) || [];

function displayMessages(messages, referenceTime) {
    const chatBox = document.getElementById('chat-box');
    if (!chatBox) {
        console.error("Chat box element not found");
        return;
    }
    chatBox.innerHTML = '';
    const currentTime = referenceTime || Date.now();
    const validMessages = messages.filter(msgObj => {
        if (typeof msgObj === 'string') return true;
        const messageAge = currentTime - msgObj.timestamp;
        return messageAge <= 300000;
    });

    if (validMessages.length !== messages.length) {
        localMessages = validMessages;
        saveLocalMessages(localMessages);
    }

    validMessages.forEach(msgObj => {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message';
        let name, content;
        if (typeof msgObj === 'string') {
            name = 'Anonymous';
            content = msgObj;
        } else {
            name = msgObj.name || 'Anonymous';
            content = msgObj.content;
        }
        messageDiv.innerHTML = `
            <span class="message-name">${escapeHtml(name)}</span>
            <span class="message-text">${escapeHtml(content)}</span>
        `;
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
    
    const chatBox = document.getElementById('chat-box');
    if (!chatBox) {
        console.error("Chat box element not found in fetchMessages");
        return;
    }

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
                    return { name: decrypted.name, content: decrypted.message, timestamp };
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
    const chatBox = document.getElementById('chat-box');
    if (!chatBox) {
        console.error("Chat box element not found in initializeChat");
        return;
    }

    try {
        if (typeof serverMessages !== 'undefined' && serverMessages.length > 0) {
            const decryptedServerMessages = await Promise.all(
                serverMessages.map(async (enc, index) => {
                    const decrypted = await decryptMessage(enc);
                    if (decrypted !== null) {
                        return {
                            name: decrypted.name,
                            content: decrypted.message,
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
        
        setInterval(fetchMessages, 2000);
        setInterval(() => {
            displayMessages(localMessages);
        }, 60000);
        
    } catch (error) {
        console.error("Error initializing chat:", error);
    }
}

function clearChat() {
    const msgInput = document.getElementById('message-input');
    if (msgInput) msgInput.value = '';
}

async function handleFormSubmit(e) {
    e.preventDefault();
    const chatBox = document.getElementById('chat-box');
    if (!chatBox) {
        console.error("Chat box element not found in handleFormSubmit");
        alert("Chat box not found. Please refresh the page.");
        return;
    }
    if (!derivedKey) {
        alert("Encryption key not ready. Please wait or reset the key.");
        return;
    }
    
    const msgInput = document.getElementById('message-input');
    let message = sanitizeInput(msgInput.value);
    const displayName = sessionStorage.getItem('displayName') || 'Anonymous';
    if (message && message.length > 0) {
        if (displayName.length + message.length > 1000) {
            alert('Combined name and message too long (max 1000 characters)');
            return;
        }
        try {
            const encrypted = await encryptMessage(message);
            const timestamp = parseInt(encrypted.split(':')[2]);
            
            const formData = new FormData();
            formData.append('encrypted_message', encrypted);
            
            const response = await fetch(window.location.href, {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            if (!data.success) {
                throw new Error(`Server rejected message: ${data.error || 'Unknown error'}`);
            }
            
            localMessages.push({ name: displayName, content: message, timestamp });
            displayMessages(localMessages);
            saveLocalMessages(localMessages);
            
            msgInput.value = '';
            lastActivity = Date.now();
        } catch (error) {
            console.error("Error sending message:", error);
            alert("Failed to send message: " + error.message);
        }
    }
}

setInterval(() => {
    console.log("Periodic timeout check at", new Date().toLocaleTimeString());
    if (Date.now() - lastActivity > 30 * 60 * 1000) {
        resetChatKey();
        alert('Session expired due to inactivity');
    }
}, 60000);

document.addEventListener('DOMContentLoaded', async () => {
    await initializeFromStorage();
    
    document.getElementById('submit-key-btn').addEventListener('click', submitKey);
    document.getElementById('clear-btn').addEventListener('click', clearChat);
    document.getElementById('reset-key-btn').addEventListener('click', resetChatKey);
    document.getElementById('go-public-btn').addEventListener('click', () => {
        location.href = 'talk_silver.php';
    });
    document.getElementById('accept-consent').addEventListener('click', acceptConsent);
    document.getElementById('reject-consent').addEventListener('click', rejectConsent);
    
    const chatForm = document.getElementById('chat-form');
    if (chatForm) {
        chatForm.addEventListener('submit', handleFormSubmit);
    }

    document.addEventListener('click', () => lastActivity = Date.now());
    document.addEventListener('keypress', () => lastActivity = Date.now());
    const msgInput = document.getElementById('message-input');
    if (msgInput) {
        msgInput.addEventListener('input', () => lastActivity = Date.now());
    }
});
