<?php
// Database Configuration
$host = "localhost";
$user = "root";
$pass = "";
$dbname = "pharmacy_db";

// Start session with secure settings
if (session_status() === PHP_SESSION_NONE) {
    // Configure session security
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_only_cookies', 1);
    ini_set('session.cookie_secure', 0); // Set to 1 if using HTTPS
    ini_set('session.cookie_samesite', 'Strict');
    
    session_start();
}

// Prevent session fixation - regenerate ID on login
function regenerateSessionId() {
    session_regenerate_id(true);
}

// Check if user is logged in
function isLoggedIn() {
    return isset($_SESSION['user_id']) && isset($_SESSION['username']);
}

// Require login - redirect to login page if not authenticated
function requireLogin() {
    if (!isLoggedIn()) {
        header("Location: login.php");
        exit;
    }
}

// Get current user info
function getCurrentUser() {
    if (isLoggedIn()) {
        return [
            'id' => $_SESSION['user_id'],
            'username' => $_SESSION['username'],
            'email' => $_SESSION['email'] ?? '',
            'full_name' => $_SESSION['full_name'] ?? '',
            'role' => $_SESSION['role'] ?? 'nurse'
        ];
    }
    return null;
}

function hasRole($role) {
    return isLoggedIn() && isset($_SESSION['role']) && $_SESSION['role'] === $role;
}

function requireRole($role) {
    if (!hasRole($role)) {
        http_response_code(403);
        echo "Access denied. {$role} role required.";
        exit;
    }
}

// Database Connection
$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Set charset to utf8mb4 for proper character support
$conn->set_charset("utf8mb4");

// Ensure users table exists
function ensureUsersTableExists($conn) {
    $createTableQuery = "CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        email VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        full_name VARCHAR(100) NOT NULL,
        role ENUM('doctor','nurse','pharmacist','staff') NOT NULL DEFAULT 'nurse',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP NULL,
        INDEX idx_username (username),
        INDEX idx_email (email)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

    $conn->query($createTableQuery);
}

// Ensure existing table has role column
function ensureRoleColumnExists($conn, $dbname) {
    $stmt = $conn->prepare("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'users' AND COLUMN_NAME = 'role'");
    if ($stmt) {
        $stmt->bind_param("s", $dbname);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            $conn->query("ALTER TABLE users ADD COLUMN role ENUM('doctor','nurse','pharmacist','staff') NOT NULL DEFAULT 'nurse' AFTER full_name");
        }

        $stmt->close();
    }
}

// Seed default user if none exists
function ensureDefaultUser($conn) {
    $defaultUsername = 'gilbert';
    $defaultEmail = 'gilbert@example.com';

    $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
    if ($stmt) {
        $stmt->bind_param("ss", $defaultUsername, $defaultEmail);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            $hashedPassword = password_hash('tumba123', PASSWORD_BCRYPT);
            $fullName = 'Gilbert Tumba';
            $role = 'doctor';

            $insertStmt = $conn->prepare("INSERT INTO users (username, email, password, full_name, role) VALUES (?, ?, ?, ?, ?)");
            if ($insertStmt) {
                $insertStmt->bind_param("sssss", $defaultUsername, $defaultEmail, $hashedPassword, $fullName, $role);
                $insertStmt->execute();
                $insertStmt->close();
            }
        } else {
            // Ensure Gilbert remains doctor
            $updateStmt = $conn->prepare("UPDATE users SET role = 'doctor' WHERE username = ?");
            if ($updateStmt) {
                $updateStmt->bind_param("s", $defaultUsername);
                $updateStmt->execute();
                $updateStmt->close();
            }
        }

        $stmt->close();
    }
}

ensureUsersTableExists($conn);
ensureRoleColumnExists($conn, $dbname);
ensureDefaultUser($conn);

// Sanitize input function
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

// Validate email
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

// Validate password strength (minimum 6 characters)
function validatePassword($password) {
    return strlen($password) >= 6;
}

?>

