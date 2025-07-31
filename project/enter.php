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

// Force HTTPS
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit();
}
?>

<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> 
    <title>Encrypted Timed Chat</title>
    <link rel="stylesheet" href="style-6.css">
</head>
<body>
    <div class="container landing-page">
        <div class="header">Multi-User Timed Encrypted Chat <sup>MUTE</sup></div>
        <div class="content">
            <!-- Progress indicator -->
            <div class="lp-progress-dots">
                <div class="lp-progress-dot active" id="lp-dot-1"></div>
                <div class="lp-progress-dot" id="lp-dot-2"></div>
            </div>

            <div class="lp-form-stack">
                <div class="lp-form-card" id="name-entry">
                    <label for="display-name-input" class="lp-name-label">Enter your display name:</label>
                    <input type="text" id="display-name-input" class="lp-name-input" placeholder="Your name (max 20 characters)" maxlength="20" required>
                    <button type="button" id="submit-name-btn" class="lp-submit-name-btn">Submit Name</button>
                </div>
                
                <div class="lp-form-card" id="room-selection" style="display: none;">
                    <h3 class="lp-room-title">Choose a Chat Room</h3>
                    <div class="lp-room-buttons">
                        <button type="button" id="go-public-btn" class="lp-room-btn">Public Chat</button>
                        <button type="button" id="go-private-btn" class="lp-room-btn">Private Chat</button>
                    </div>
                </div>
            </div>

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
        // Consent handling
        function acceptConsent() {
            if (typeof(Storage) !== "undefined") {
                try {
                    sessionStorage.setItem('cookieConsent', 'true');
                } catch(e) {
                    console.log('Session storage not available');
                }
            }
            document.getElementById('consent-box').style.display = 'none';
        }

        function rejectConsent() {
            alert("Chat requires session storage. Please accept or leave.");
            document.getElementById('consent-box').style.display = 'none';
            window.location.href = "about:blank";
        }

        // Check consent on load
        if (typeof(Storage) !== "undefined") {
            try {
                if (!sessionStorage.getItem('cookieConsent')) {
                    document.getElementById('consent-box').style.display = 'block';
                }
            } catch(e) {
                document.getElementById('consent-box').style.display = 'block';
            }
        }

        // Name submission with progress update
        function submitName() {
            const nameInput = document.getElementById('display-name-input').value.trim();
            
            // Allow empty names - use "Anonymous" as default
            let displayName = nameInput || "Anonymous";
            
            // Sanitize name to prevent XSS
            const sanitizedName = displayName.replace(/[<>\"'&]/g, '');
            if (sanitizedName.length > 20) {
                alert('Display name too long (max 20 characters).');
                return;
            }
            
            if (typeof(Storage) !== "undefined") {
                try {
                    sessionStorage.setItem('displayName', sanitizedName);
                } catch(e) {
                    console.log('Session storage not available');
                }
            }
            
            // Update progress dots
            document.getElementById('lp-dot-1').classList.remove('active');
            document.getElementById('lp-dot-1').classList.add('completed');
            document.getElementById('lp-dot-2').classList.add('active');
            
            // Smooth transition
            document.getElementById('name-entry').style.display = 'none';
            document.getElementById('room-selection').style.display = 'block';
        }

        // Event listeners
        document.addEventListener('DOMContentLoaded', () => {
            document.getElementById('submit-name-btn').addEventListener('click', submitName);
            document.getElementById('go-private-btn').addEventListener('click', () => {
                window.location.href = 'talk_gold.php';
            });
            document.getElementById('go-public-btn').addEventListener('click', () => {
                window.location.href = 'talk_silver.php';
            });
            document.getElementById('accept-consent').addEventListener('click', acceptConsent);
            document.getElementById('reject-consent').addEventListener('click', rejectConsent);
            
            // Allow Enter key to submit name
            document.getElementById('display-name-input').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    submitName();
                }
            });
        });
    </script>
</body>
</html>