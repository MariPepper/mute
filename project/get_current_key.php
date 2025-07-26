<?php
$keyFile = '../private/session_key.json';

if (file_exists($keyFile)) {
    $data = json_decode(file_get_contents($keyFile), true);
    if ($data && isset($data['keys']) && is_array($data['keys']) && !empty($data['keys'])) {
        $keys = $data['keys']; // Array of keys, e.g., ['base64string1', 'base64string2', ...]
        
        // Calculate position based on current 5-minute window
        $offset = $data['offset'] ?? 0;
        $timeWindow = floor((time() - $offset) / 300);
        
        // Dynamic salt: hash of offset + current day (YYYYMMDD)
        $dayHour = date('YmdH');
        $salt = hexdec(substr(md5($offset . $dayHour), 0, 8)); // 32-bit int from hash
        $obfuscatedWindow = $timeWindow ^ $salt;
        $position = $obfuscatedWindow % count($keys);
        
        // Ensure position is non-negative
        $position = ($position < 0) ? $position + count($keys) : $position;
        
        $currentKey = $keys[$position];
        
        header('Content-Type: application/json');
        echo json_encode(['key' => $currentKey]);
        exit;
    }
}

// No valid key found
header('Content-Type: application/json');
echo json_encode(['error' => 'No valid key found']);
?>