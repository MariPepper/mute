<?php
header('Content-Type: application/json');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $x = $input['x'] ?? 0;
    if (!is_numeric($x) || $x < 0) {
        echo json_encode(['error' => 'Invalid input']);
        exit;
    }
    try {
        $randomNum = gmp_strval(gmp_powm(2, $x, 2147483647));
        echo json_encode(['randomNum' => $randomNum]);
    } catch (Exception $e) {
        echo json_encode(['error' => 'Modular exponentiation failed']);
    }
} else {
    echo json_encode(['error' => 'Invalid request']);
}
?>