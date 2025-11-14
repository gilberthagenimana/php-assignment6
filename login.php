<?php
require_once 'config.php';

$error = '';

// Check if already logged in
if (isLoggedIn()) {
    header("Location: Pharmacy.PHP");
    exit;
}

// Check for remember me cookie
if (isset($_COOKIE['remember_token']) && !isLoggedIn()) {
    $token = $_COOKIE['remember_token'];
    
    // In a real application, you'd have a remember_tokens table
    // For simplicity, we'll decode and verify the token
    $token_data = base64_decode($token);
    $parts = explode(':', $token_data);
    
    if (count($parts) == 2) {
        $username = $parts[0];
        $token_hash = $parts[1];
        
        // Verify token (in production, check against database)
        $stmt = $conn->prepare("SELECT id, username, email, full_name, role FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            
            // Set session
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['role'] = $user['role'];
            
            regenerateSessionId();
            
            header("Location: Pharmacy.PHP");
            exit;
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = sanitizeInput($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $remember_me = isset($_POST['remember_me']) && $_POST['remember_me'] == '1';
    
    if (empty($username) || empty($password)) {
        $error = "Username and password are required";
    } else {
        // Get user from database
        $stmt = $conn->prepare("SELECT id, username, email, password, full_name, role FROM users WHERE username = ? OR email = ?");
        $stmt->bind_param("ss", $username, $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            
            // Verify password
            if (password_verify($password, $user['password'])) {
                // Set session variables
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['full_name'] = $user['full_name'];
                $_SESSION['role'] = $user['role'];
                
                // Regenerate session ID to prevent session fixation
                regenerateSessionId();
                
                // Update last login
                $stmt = $conn->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
                $stmt->bind_param("i", $user['id']);
                $stmt->execute();
                
                // Handle "Remember Me" cookie
                if ($remember_me) {
                    // Create a simple token (in production, use a proper token system)
                    $token = base64_encode($user['username'] . ':' . hash('sha256', $user['username'] . $user['password'] . time()));
                    
                    // Set cookie for 30 days
                    setcookie('remember_token', $token, time() + (30 * 24 * 60 * 60), '/', '', false, true); // httponly flag
                }
                
                // Redirect to main page
                header("Location: Pharmacy.PHP");
                exit;
            } else {
                $error = "Invalid username or password";
            }
        } else {
            $error = "Invalid username or password";
        }
        $stmt->close();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Pharmacy Management System</title>
    <style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    color: #333;
}

.auth-container {
    max-width: 450px;
    width: 100%;
    background: white;
    border-radius: 12px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
    padding: 40px;
}

h1 {
    color: #667eea;
    font-size: 2em;
    margin-bottom: 10px;
    text-align: center;
    font-weight: 700;
}

.subtitle {
    text-align: center;
    color: #666;
    margin-bottom: 30px;
    font-size: 14px;
}

.form-group {
    margin-bottom: 20px;
}

label {
    display: block;
    margin-bottom: 8px;
    color: #667eea;
    font-weight: 600;
    font-size: 14px;
}

input[type="text"],
input[type="email"],
input[type="password"] {
    width: 100%;
    padding: 12px 16px;
    border: 2px solid #e0e0e0;
    border-radius: 8px;
    font-size: 16px;
    transition: all 0.3s ease;
    background: white;
    font-family: inherit;
}

input[type="text"]:focus,
input[type="email"]:focus,
input[type="password"]:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.checkbox-group {
    display: flex;
    align-items: center;
    margin-bottom: 20px;
}

.checkbox-group input[type="checkbox"] {
    width: auto;
    margin-right: 8px;
    cursor: pointer;
}

.checkbox-group label {
    margin: 0;
    font-weight: 400;
    color: #666;
    cursor: pointer;
}

button[type="submit"] {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 14px 28px;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    margin-top: 10px;
    box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
    width: 100%;
}

button[type="submit"]:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
}

.error {
    background: #ffebee;
    color: #c62828;
    padding: 12px 16px;
    border-radius: 8px;
    margin-bottom: 20px;
    border-left: 4px solid #f44336;
    font-weight: 500;
}

.signup-link {
    text-align: center;
    margin-top: 20px;
    color: #666;
    font-size: 14px;
}

.signup-link a {
    color: #667eea;
    text-decoration: none;
    font-weight: 600;
}

.signup-link a:hover {
    text-decoration: underline;
}

@media (max-width: 768px) {
    .auth-container {
        padding: 30px 20px;
    }
    
    h1 {
        font-size: 1.5em;
    }
}
    </style>
</head>
<body>
    <div class="auth-container">
        <h1>🔑 Login</h1>
        <p class="subtitle">Access your Pharmacy Management System</p>
        
        <?php if($error): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        
        <form method="POST" action="">
            <div class="form-group">
                <label for="username">Username or Email *</label>
                <input type="text" id="username" name="username" placeholder="Enter username or email" value="<?= htmlspecialchars($username ?? '') ?>" required autofocus>
            </div>
            
            <div class="form-group">
                <label for="password">Password *</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            
            <div class="checkbox-group">
                <input type="checkbox" id="remember_me" name="remember_me" value="1">
                <label for="remember_me">Remember me for 30 days</label>
            </div>
            
            <button type="submit">🚀 Login</button>
        </form>
        
        <div class="signup-link">
            Don't have an account? <a href="signup.php">Sign up here</a>
        </div>
    </div>
</body>
</html>

