<?php
header("Expires: 0");
header("Cache-Control: no-store, no-cache, must-revalidate");
header("Pragma: no-cache");
header('Content-Type: application/json');

if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    header("Location: https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
    exit();
}

$chatFile = 'temp_talk_silver.json';
$messageExpirationTime = 300; // 5 minutes in seconds

function loadMessages($file, $expirationTime)
{
    try {
        $currentTime = time();
        
        if (file_exists($file)) {
            $data = json_decode(file_get_contents($file), true);
            
            if ($data && isset($data['messages'])) {
                $messages = [];
                
                foreach ($data['messages'] as $message) {
                    if (!isset($message['timestamp'])) {
                        error_log("Message missing timestamp: " . json_encode($message));
                        continue;
                    }
                    $timeSinceMessage = $currentTime - $message['timestamp'];
                    if ($timeSinceMessage < $expirationTime) {
                        $messages[] = [
                            'content' => $message['content'],
                            'timestamp' => $message['timestamp']
                        ];
                    } else {
                        error_log("Expiring message: " . json_encode($message) . " (age: $timeSinceMessage seconds)");
                    }
                }
                
                if (count($messages) !== count($data['messages'])) {
                    saveMessages($file, $messages, $currentTime);
                }
                
                error_log("Returning " . count($messages) . " messages after filtering");
                return $messages;
            }
        }
        return [];
    } catch (Exception $e) {
        error_log("Error loading messages: " . $e->getMessage());
        return [];
    }
}

function saveMessages($file, $messages, $timestamp)
{
    try {
        $data = [
            'messages' => $messages,
            'last_activity' => $timestamp
        ];
        if (!file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX)) {
            error_log("Failed to write messages to $file in saveMessages");
            return false;
        }
        chmod($file, 0600);
        error_log("Saved messages: " . count($messages) . " at " . date('Y-m-d H:i:s', $timestamp));
        return true;
    } catch (Exception $e) {
        error_log("Error saving messages: " . $e->getMessage());
        return false;
    }
}

try {
    $messages = loadMessages($chatFile, $messageExpirationTime);
    echo json_encode($messages);
} catch (Exception $e) {
    error_log("Error in fetch_messages_silver.php: " . $e->getMessage());
    echo json_encode(['success' => false, 'error' => 'Failed to fetch messages']);
}
?>