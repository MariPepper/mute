<?php
header('Content-Type: application/json');

if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit();
}

$chatFile = 'temp_talk_gold.json';

function loadMessages($file) {
    if (file_exists($file)) {
        $data = json_decode(file_get_contents($file), true);
        if ($data && isset($data['messages'])) {
            $currentTime = time();
            // Only clean if last cleanup was more than 60 seconds ago
            if (!isset($data['last_cleanup']) || ($currentTime - $data['last_cleanup']) > 60) {
                $validMessages = array_filter($data['messages'], function($message) use ($currentTime) {
                    if (is_string($message)) {
                        return true; // Keep legacy messages for migration
                    }
                    return isset($message['timestamp']) && ($currentTime - $message['timestamp']) < 300; // 5 minutes
                });
                $validMessages = array_values($validMessages);
                if (count($validMessages) !== count($data['messages'])) {
                    $expiredCount = count($data['messages']) - count($validMessages);
                    error_log("Cleaned $expiredCount expired messages at " . date('Y-m-d H:i:s'));
                    saveMessages($file, $validMessages, $currentTime);
                }
                return $validMessages;
            }
            return $data['messages'];
        }
    }
    return [];
}

function saveMessages($file, $messages, $timestamp) {
    $data = ['messages' => $messages, 'last_activity' => $timestamp, 'last_cleanup' => $timestamp];
    file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
    chmod($file, 0600);
}

$response = [
    'messages' => loadMessages($chatFile),
    'server_time' => time()
];
echo json_encode($response);
?>