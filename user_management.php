<?php
require_once 'config.php';
requireLogin();
requireRole('doctor');
$currentUser = getCurrentUser();

$allowedRoles = ['doctor','nurse','pharmacist','staff'];
$error = '';
$success = '';
$isEditing = false;
$editUser = null;

// Determine if editing a user
if (isset($_GET['action']) && $_GET['action'] === 'edit' && isset($_GET['id'])) {
    $editId = intval($_GET['id']);
    $stmt = $conn->prepare("SELECT id, full_name, username, email, role FROM users WHERE id = ?");
    if ($stmt) {
        $stmt->bind_param("i", $editId);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows === 1) {
            $editUser = $result->fetch_assoc();
            $isEditing = true;
        } else {
            $error = "User not found.";
        }
        $stmt->close();
    }
}

// Handle delete request
if (isset($_GET['action']) && $_GET['action'] === 'delete' && isset($_GET['id'])) {
    $userId = intval($_GET['id']);

    if ($userId === $_SESSION['user_id']) {
        $error = "You cannot delete your own account while logged in.";
    } else {
        $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
        if ($stmt) {
            $stmt->bind_param("i", $userId);
            if ($stmt->execute()) {
                $success = "User deleted successfully.";
            } else {
                $error = "Failed to delete user.";
            }
            $stmt->close();
        } else {
            $error = "Unable to process delete request.";
        }
    }
}

// Handle add/update user form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $full_name = sanitizeInput($_POST['full_name'] ?? '');
    $username = sanitizeInput($_POST['username'] ?? '');
    $email = sanitizeInput($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $role = sanitizeInput($_POST['role'] ?? 'nurse');
    $editId = isset($_POST['edit_id']) && $_POST['edit_id'] !== '' ? intval($_POST['edit_id']) : null;

    if (!in_array($role, $allowedRoles)) {
        $role = 'nurse';
    }

    if (empty($full_name) || empty($username) || empty($email)) {
        $error = "Full name, username and email are required.";
    } elseif (!$editId && (empty($password) || empty($confirm_password))) {
        $error = "Password and confirmation are required for new users.";
    } elseif (!validateEmail($email)) {
        $error = "Invalid email format.";
    } elseif (!$editId && !validatePassword($password)) {
        $error = "Password must be at least 6 characters long.";
    } elseif ($password !== $confirm_password) {
        if (!empty($password) || !empty($confirm_password)) {
            $error = "Passwords do not match.";
        }
    } elseif (strlen($username) < 3) {
        $error = "Username must be at least 3 characters long.";
    } else {
        $stmt = $conn->prepare("SELECT id FROM users WHERE (username = ? OR email = ?) AND (? IS NULL OR id <> ?)");
        if ($stmt) {
            $nullCheck = $editId;
            $stmt->bind_param("ssii", $username, $email, $nullCheck, $nullCheck);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $error = "Username or email already exists.";
            } else {
                if ($editId) {
                    // Update existing user
                    if (!empty($password)) {
                        if (!validatePassword($password)) {
                            $error = "Password must be at least 6 characters long.";
                        } else {
                            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
                            $updateStmt = $conn->prepare("UPDATE users SET username=?, email=?, password=?, full_name=?, role=? WHERE id=?");
                            if ($updateStmt) {
                                $updateStmt->bind_param("sssssi", $username, $email, $hashedPassword, $full_name, $role, $editId);
                                if ($updateStmt->execute()) {
                                    $success = "User updated successfully.";
                                    if ($editId === $_SESSION['user_id']) {
                                        $_SESSION['username'] = $username;
                                        $_SESSION['email'] = $email;
                                        $_SESSION['full_name'] = $full_name;
                                        $_SESSION['role'] = $role;
                                    }
                                    header("Location: user_management.php");
                                    exit;
                                } else {
                                    $error = "Failed to update user.";
                                }
                                $updateStmt->close();
                            } else {
                                $error = "Unable to update user.";
                            }
                        }
                    } else {
                        $updateStmt = $conn->prepare("UPDATE users SET username=?, email=?, full_name=?, role=? WHERE id=?");
                        if ($updateStmt) {
                            $updateStmt->bind_param("ssssi", $username, $email, $full_name, $role, $editId);
                            if ($updateStmt->execute()) {
                                $success = "User updated successfully.";
                                if ($editId === $_SESSION['user_id']) {
                                    $_SESSION['username'] = $username;
                                    $_SESSION['email'] = $email;
                                    $_SESSION['full_name'] = $full_name;
                                    $_SESSION['role'] = $role;
                                }
                                header("Location: user_management.php");
                                exit;
                            } else {
                                $error = "Failed to update user.";
                            }
                            $updateStmt->close();
                        } else {
                            $error = "Unable to update user.";
                        }
                    }
                } else {
                    // Create new user
                    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
                    $insertStmt = $conn->prepare("INSERT INTO users (username, email, password, full_name, role) VALUES (?, ?, ?, ?, ?)");
                    if ($insertStmt) {
                        $insertStmt->bind_param("sssss", $username, $email, $hashedPassword, $full_name, $role);
                        if ($insertStmt->execute()) {
                            $success = "User account created successfully.";
                            $full_name = $username = $email = '';
                        } else {
                            $error = "Failed to create user.";
                        }
                        $insertStmt->close();
                    } else {
                        $error = "Unable to create user.";
                    }
                }
            }
            $stmt->close();
        } else {
            $error = "Unable to validate user details.";
        }
    }
}

$formTitle = $isEditing ? "Edit User" : "Create New User";
$submitLabel = $isEditing ? "💾 Update User" : "➕ Create User";
$noteText = $isEditing ? "Leave password blank to keep the current one." : 'Self sign-up remains available for non-doctor staff (defaults to "Nurse" role).';

$users = $conn->query("SELECT id, username, email, full_name, role, created_at, last_login FROM users ORDER BY FIELD(role, 'doctor','pharmacist','nurse','staff'), username ASC");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management - Pharmacy Management System</title>
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
    padding: 20px;
    color: #333;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    background: white;
    border-radius: 12px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
    padding: 30px;
}

.header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 15px;
    margin-bottom: 30px;
    border-bottom: 2px solid #f0f0f0;
    padding-bottom: 20px;
}

.header-title {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.header-title h1 {
    color: #667eea;
    font-size: 2em;
    margin: 0;
}

.user-info {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
    color: #666;
}

.role-pill {
    padding: 6px 12px;
    border-radius: 20px;
    background: #eef1ff;
    font-size: 12px;
    color: #4c5bd4;
    font-weight: 600;
    letter-spacing: 0.5px;
}

.btn {
    display: inline-block;
    padding: 10px 20px;
    border-radius: 8px;
    border: none;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    text-decoration: none;
    font-weight: 600;
    transition: all 0.3s ease;
    cursor: pointer;
    box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
}

.btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
}

.btn.logout {
    background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
}

.btn.secondary {
    background: linear-gradient(135deg, #00c6ff 0%, #0072ff 100%);
}

.section-title {
    margin: 30px 0 15px;
    color: #667eea;
    font-size: 1.4em;
}

.message {
    padding: 12px 16px;
    border-radius: 8px;
    margin-bottom: 20px;
}

.message.error {
    background: #ffebee;
    color: #c62828;
    border-left: 4px solid #f44336;
}

.message.success {
    background: #e8f5e9;
    color: #2e7d32;
    border-left: 4px solid #4caf50;
}

.form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 20px;
}

label {
    display: block;
    margin-bottom: 6px;
    font-weight: 600;
    color: #667eea;
    font-size: 14px;
}

input[type="text"],
input[type="email"],
input[type="password"],
select {
    width: 100%;
    padding: 12px;
    border: 2px solid #e0e0e0;
    border-radius: 8px;
    font-size: 15px;
    transition: border 0.2s ease;
}

input:focus,
select:focus {
    border-color: #667eea;
    outline: none;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.2);
}

.user-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 2px 10px rgba(0,0,0,0.08);
}

.user-table thead {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}

.user-table th,
.user-table td {
    padding: 12px 15px;
    text-align: left;
    font-size: 14px;
}

.user-table tbody tr:nth-child(even) {
    background: #f8f9ff;
}

.user-table tbody tr:hover {
    background: #eef2ff;
}

.actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}

.btn.delete {
    background: linear-gradient(135deg, #ff5f6d 0%, #ffc371 100%);
}

.note {
    margin-top: 10px;
    font-size: 13px;
    color: #777;
}

@media (max-width: 768px) {
    .form-grid {
        grid-template-columns: 1fr;
    }
}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-title">
                <h1>User Management</h1>
                <p>Only doctors can access this page. Use it to create staff accounts.</p>
            </div>
            <div class="user-info">
                <span>👤 <?= htmlspecialchars($currentUser['full_name']) ?> (<?= htmlspecialchars($currentUser['username']) ?>)</span>
                <span class="role-pill"><?= strtoupper(htmlspecialchars($currentUser['role'])) ?></span>
                <a href="Pharmacy.PHP" class="btn secondary">← Back to Dashboard</a>
                <a href="logout.php" class="btn logout">🚪 Logout</a>
            </div>
        </div>

        <h2 class="section-title"><?= $formTitle ?></h2>

        <?php if ($error): ?>
            <div class="message error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="message success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <form method="POST">
            <input type="hidden" name="edit_id" value="<?= $isEditing ? intval($editUser['id']) : '' ?>">
            <div class="form-grid">
                <div>
                    <label for="full_name">Full Name *</label>
                    <input type="text" id="full_name" name="full_name" value="<?= htmlspecialchars($isEditing ? $editUser['full_name'] : ($full_name ?? '')) ?>" required>
                </div>
                <div>
                    <label for="username">Username *</label>
                    <input type="text" id="username" name="username" value="<?= htmlspecialchars($isEditing ? $editUser['username'] : ($username ?? '')) ?>" required minlength="3">
                </div>
                <div>
                    <label for="email">Email *</label>
                    <input type="email" id="email" name="email" value="<?= htmlspecialchars($isEditing ? $editUser['email'] : ($email ?? '')) ?>" required>
                </div>
                <div>
                    <label for="role">Role *</label>
                    <select id="role" name="role" required>
                        <?php foreach ($allowedRoles as $roleOption): ?>
                            <?php
                                $selectedRole = $isEditing ? $editUser['role'] : ($role ?? 'nurse');
                            ?>
                            <option value="<?= $roleOption ?>" <?= ($selectedRole === $roleOption) ? 'selected' : '' ?>>
                                <?= ucfirst($roleOption) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div>
                    <label for="password">Password *</label>
                    <input type="password" id="password" name="password" <?= $isEditing ? '' : 'required' ?> minlength="6">
                </div>
                <div>
                    <label for="confirm_password">Confirm Password *</label>
                    <input type="password" id="confirm_password" name="confirm_password" <?= $isEditing ? '' : 'required' ?> minlength="6">
                </div>
            </div>
            <button type="submit" class="btn" style="margin-top: 20px;"><?= $submitLabel ?></button>
            <p class="note"><?= $noteText ?></p>
            <?php if ($isEditing): ?>
                <p class="note"><a href="user_management.php">Cancel editing</a></p>
            <?php endif; ?>
        </form>

        <h2 class="section-title">Existing Users</h2>

        <?php if ($users && $users->num_rows > 0): ?>
            <div class="table-wrapper">
                <table class="user-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Full Name</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Created</th>
                            <th>Last Login</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($user = $users->fetch_assoc()): ?>
                            <tr>
                                <td><?= $user['id'] ?></td>
                                <td><?= htmlspecialchars($user['full_name']) ?></td>
                                <td><?= htmlspecialchars($user['username']) ?></td>
                                <td><?= htmlspecialchars($user['email']) ?></td>
                                <td><span class="role-pill"><?= strtoupper(htmlspecialchars($user['role'])) ?></span></td>
                                <td><?= htmlspecialchars(date('Y-m-d', strtotime($user['created_at']))) ?></td>
                                <td><?= $user['last_login'] ? htmlspecialchars(date('Y-m-d H:i', strtotime($user['last_login']))) : 'Never' ?></td>
                                <td>
                                    <div class="actions">
                                        <a href="user_management.php?action=edit&id=<?= $user['id'] ?>" class="btn secondary">Edit</a>
                                        <?php if ($user['id'] !== $_SESSION['user_id']): ?>
                                            <a href="user_management.php?action=delete&id=<?= $user['id'] ?>" class="btn delete" onclick="return confirm('Delete this user?');">Delete</a>
                                        <?php else: ?>
                                            <em>Current user</em>
                                        <?php endif; ?>
                                    </div>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        <?php else: ?>
            <p>No users found.</p>
        <?php endif; ?>
    </div>
</body>
</html>

