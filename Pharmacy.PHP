<?php
// Include configuration and authentication functions
require_once 'config.php';

// Require login for all pages
requireLogin();

// Get current user information
$currentUser = getCurrentUser();

// Sanitize action parameter
$action = isset($_GET['action']) ? sanitizeInput($_GET['action']) : 'list';

if ($action == 'delete' && isset($_GET['id']) && !empty($_GET['id'])) {
    $id = intval($_GET['id']);
    $stmt = $conn->prepare("DELETE FROM medicines WHERE id = ?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute()) {
        header("Location: Pharmacy.PHP");
        exit;
    }
    $stmt->close();
}


if ($action == 'list' || $action == '') {
$result = $conn->query("SELECT * FROM medicines ORDER BY id ASC");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pharmacy Management System</title>
   <link rel="stylesheet" href="pharmacy.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>Pharmacy Medicines List</h1>
                <div class="user-info">
                    <span>👤 Logged in as: <strong><?= htmlspecialchars($currentUser['full_name']) ?> (<?= htmlspecialchars($currentUser['username']) ?>)</strong></span>
                    <span class="role-pill"><?= strtoupper(htmlspecialchars($currentUser['role'])) ?></span>
                    <a href="logout.php" class="btn logout">🚪 Logout</a>
                </div>
            </div>
            <div class="actions">
                <?php if ($currentUser['role'] === 'doctor'): ?>
                    <a href="user_management.php" class="btn manage">⚙️ Manage Users</a>
                <?php endif; ?>
                <a href="Pharmacy.PHP?action=create" class="btn">➕ Add New Medicine</a>
            </div>
        </div>

        <?php if($result->num_rows > 0): ?>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Category</th>
                    <th>Quantity</th>
                    <th>Price</th>
                    <th>Expiry Date</th>
                    <th>Supplier</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php while($row = $result->fetch_assoc()): ?>
                <tr>
                    <td><?= htmlspecialchars($row['id']) ?></td>
                    <td><strong><?= htmlspecialchars($row['medicine_name']) ?></strong></td>
                    <td><?= htmlspecialchars($row['category']) ?></td>
                    <td><?= htmlspecialchars($row['quantity']) ?></td>
                    <td><strong>Rwf <?= number_format((float)$row['price'], 2) ?></strong></td>
                    <td><?= htmlspecialchars($row['expiry_date']) ?></td>
                    <td><?= htmlspecialchars($row['supplier']) ?></td>
                    <td>
                        <a href="Pharmacy.PHP?action=edit&id=<?= $row['id'] ?>" class="btn edit">Edit</a>
                        <a href="Pharmacy.PHP?action=delete&id=<?= $row['id'] ?>" class="btn delete" onclick="return confirm('Are you sure you want to delete this medicine?')">Delete</a>
                    </td>
                </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
        <?php else: ?>
        <div class="empty-state">
            <h3>No medicines found</h3>
            <p>Start by adding your first medicine to the system.</p>
        </div>
        <?php endif; ?>
    </div>
</body>
</html>

<?php
} elseif ($action == 'create') {
    if (isset($_POST['submit'])) {
    // Sanitize all inputs
    $name = sanitizeInput($_POST['medicine_name'] ?? '');
    $category = sanitizeInput($_POST['category'] ?? '');
    $qty = intval($_POST['quantity'] ?? 0);
    $price = floatval($_POST['price'] ?? 0);
    $expiry = sanitizeInput($_POST['expiry_date'] ?? '');
    $supplier = sanitizeInput($_POST['supplier'] ?? '');

    if ($name == "" || $category == "" || $qty == "" || $price == "" || $expiry == "" || $supplier == "") {
        $error = "All fields are required";
    } else {
     
        $availableId = null;
        
    
        $idResult = $conn->query("SELECT id FROM medicines ORDER BY id ASC");
        $existingIds = array();
        if ($idResult && $idResult->num_rows > 0) {
            while ($row = $idResult->fetch_assoc()) {
                $existingIds[] = (int)$row['id'];
            }
        }
        
        
        for ($i = 1; $i <= 999999; $i++) {
            if (!in_array($i, $existingIds)) {
                $availableId = $i;
                break;
            }
        }
        
    
        if ($availableId !== null) {
            $stmt = $conn->prepare("INSERT INTO medicines (id, medicine_name, category, quantity, price, expiry_date, supplier) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("issidss", $availableId, $name, $category, $qty, $price, $expiry, $supplier);
        } else {
            $stmt = $conn->prepare("INSERT INTO medicines (medicine_name, category, quantity, price, expiry_date, supplier) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("ssidss", $name, $category, $qty, $price, $expiry, $supplier);
        }

        if ($stmt->execute()) {
            header("Location: Pharmacy.PHP");
            exit;
        } else {
            $error = "Failed to save medicine";
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
    <title>Add Medicine - Pharmacy Management System</title>
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

h1 {
    color: #667eea;
    font-size: 2.5em;
    margin-bottom: 10px;
    text-align: center;
    font-weight: 700;
}

h2 {
    color: #667eea;
    font-size: 2em;
    margin-bottom: 25px;
    text-align: center;
    font-weight: 600;
}

.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 30px;
    padding-bottom: 20px;
    border-bottom: 2px solid #f0f0f0;
}

.header h1 {
    margin: 0;
    text-align: left;
}

.header h2 {
    margin: 0;
    text-align: left;
}

.user-info {
    display: flex;
    align-items: center;
    gap: 15px;
    margin-top: 10px;
    font-size: 14px;
    color: #666;
    flex-wrap: wrap;
}

.user-info span {
    color: #667eea;
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

.btn.logout {
    background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
    box-shadow: 0 4px 15px rgba(238, 90, 111, 0.4);
    padding: 8px 16px;
    font-size: 13px;
}

.btn.logout:hover {
    box-shadow: 0 6px 20px rgba(238, 90, 111, 0.6);
}

.btn.manage {
    background: linear-gradient(135deg, #00c6ff 0%, #0072ff 100%);
    box-shadow: 0 4px 15px rgba(0, 114, 255, 0.4);
}

.btn.manage:hover {
    box-shadow: 0 6px 20px rgba(0, 114, 255, 0.6);
}

.actions {
    display: flex;
    gap: 12px;
    align-items: center;
    flex-wrap: wrap;
    justify-content: flex-end;
}

.btn {
    display: inline-block;
    padding: 12px 24px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    text-decoration: none;
    border-radius: 8px;
    font-weight: 600;
    transition: all 0.3s ease;
    border: none;
    cursor: pointer;
    font-size: 14px;
    box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
}

.btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
}

.btn.edit {
    background: linear-gradient(135deg, #2196F3 0%, #21CBF3 100%);
    box-shadow: 0 4px 15px rgba(33, 150, 243, 0.4);
    margin-right: 8px;
}

.btn.edit:hover {
    box-shadow: 0 6px 20px rgba(33, 150, 243, 0.6);
}

.btn.delete {
    background: linear-gradient(135deg, #f44336 0%, #e91e63 100%);
    box-shadow: 0 4px 15px rgba(244, 67, 54, 0.4);
}

.btn.delete:hover {
    box-shadow: 0 6px 20px rgba(244, 67, 54, 0.6);
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
    background: white;
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

thead {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}

th {
    padding: 15px;
    text-align: left;
    font-weight: 600;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

td {
    padding: 15px;
    border-bottom: 1px solid #f0f0f0;
}

tbody tr {
    transition: background-color 0.2s ease;
}

tbody tr:hover {
    background-color: #f8f9ff;
}

tbody tr:last-child td {
    border-bottom: none;
}

.form-container {
    max-width: 600px;
    margin: 30px auto;
    background: #f8f9ff;
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
}

form {
    display: flex;
    flex-direction: column;
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
input[type="number"],
input[type="date"] {
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
input[type="number"]:focus,
input[type="date"]:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

button[type="submit"] {
    background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
    color: white;
    padding: 14px 28px;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    margin-top: 10px;
    box-shadow: 0 4px 15px rgba(76, 175, 80, 0.4);
    width: 100%;
}

button[type="submit"]:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(76, 175, 80, 0.6);
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

.back-btn {
    margin-bottom: 20px;
    display: inline-block;
}

.empty-state {
    text-align: center;
    padding: 60px 20px;
    color: #999;
}

.empty-state h3 {
    font-size: 1.5em;
    margin-bottom: 10px;
    color: #667eea;
}

td .btn {
    padding: 8px 16px;
    font-size: 12px;
    margin: 0 4px;
}

@media (max-width: 768px) {
    body {
        padding: 10px;
    }
    
    .container {
        padding: 20px;
    }
    
    h1 {
        font-size: 2em;
    }
    
    h2 {
        font-size: 1.5em;
    }
    
    .header {
        flex-direction: column;
        align-items: flex-start;
        gap: 15px;
    }
    
    table {
        font-size: 14px;
    }
    
    th, td {
        padding: 10px 8px;
    }
    
    .btn {
        padding: 10px 16px;
        font-size: 12px;
    }
    
    .form-container {
        padding: 20px;
    }
}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Add New Medicine</h2>
            <div class="user-info">
                <span>👤 <?= htmlspecialchars($currentUser['full_name']) ?> (<?= htmlspecialchars($currentUser['username']) ?>)</span>
                <span class="role-pill"><?= strtoupper(htmlspecialchars($currentUser['role'])) ?></span>
                <?php if ($currentUser['role'] === 'doctor'): ?>
                    <a href="user_management.php" class="btn manage">⚙️ Manage Users</a>
                <?php endif; ?>
                <a href="logout.php" class="btn logout">🚪 Logout</a>
            </div>
        </div>
        
        <div class="back-btn">
            <a href="Pharmacy.PHP" class="btn">← Back to List</a>
        </div>

        <?php if(isset($error)): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <div class="form-container">
            <form method="POST">
                <div class="form-group">
                    <label for="medicine_name">Medicine Name *</label>
                    <input type="text" id="medicine_name" name="medicine_name" placeholder="Enter medicine name" required>
                </div>

                <div class="form-group">
                    <label for="category">Category *</label>
                    <input type="text" id="category" name="category" placeholder="e.g., Antibiotic, Painkiller" required>
                </div>

                <div class="form-group">
                    <label for="quantity">Quantity *</label>
                    <input type="number" id="quantity" name="quantity" placeholder="Enter quantity" min="0" required>
                </div>

                <div class="form-group">
                    <label for="price">Price (Rwf) *</label>
                    <input type="text" id="price" name="price" placeholder="Enter price" required>
                </div>

                <div class="form-group">
                    <label for="expiry_date">Expiry Date *</label>
                    <input type="date" id="expiry_date" name="expiry_date" required>
                </div>

                <div class="form-group">
                    <label for="supplier">Supplier *</label>
                    <input type="text" id="supplier" name="supplier" placeholder="Enter supplier name" required>
                </div>

                <button type="submit" name="submit">💾 Save Medicine</button>
            </form>
        </div>
    </div>
</body>
</html>

<?php
} elseif ($action == 'edit') {

    if (isset($_GET['id']) && !empty($_GET['id'])) {
$id = intval($_GET['id']); 
$stmt = $conn->prepare("SELECT * FROM medicines WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();
$data = $result->fetch_assoc();
$stmt->close();

if (isset($_POST['update'])) {
    // Sanitize all inputs
    $name = sanitizeInput($_POST['medicine_name'] ?? '');
    $category = sanitizeInput($_POST['category'] ?? '');
    $qty = intval($_POST['quantity'] ?? 0);
    $price = floatval($_POST['price'] ?? 0);
    $expiry = sanitizeInput($_POST['expiry_date'] ?? '');
    $supplier = sanitizeInput($_POST['supplier'] ?? '');

    $stmt = $conn->prepare("UPDATE medicines SET medicine_name=?, category=?, quantity=?, price=?, expiry_date=?, supplier=? WHERE id=?");
    $stmt->bind_param("sssdssi", $name, $category, $qty, $price, $expiry, $supplier, $id);

    if ($stmt->execute()) {
            header("Location: Pharmacy.PHP");
        exit;
    } else {
        $error = "Failed to update";
    }
    $stmt->close();
    }
    }

    if (isset($data) && $data) {
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Medicine - Pharmacy Management System</title>
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

h1 {
    color: #667eea;
    font-size: 2.5em;
    margin-bottom: 10px;
    text-align: center;
    font-weight: 700;
}

h2 {
    color: #667eea;
    font-size: 2em;
    margin-bottom: 25px;
    text-align: center;
    font-weight: 600;
}

.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 30px;
    padding-bottom: 20px;
    border-bottom: 2px solid #f0f0f0;
}

.header h1 {
    margin: 0;
    text-align: left;
}

.header h2 {
    margin: 0;
    text-align: left;
}

.user-info {
    display: flex;
    align-items: center;
    gap: 15px;
    margin-top: 10px;
    font-size: 14px;
    color: #666;
    flex-wrap: wrap;
}

.user-info span {
    color: #667eea;
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

.btn.logout {
    background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
    box-shadow: 0 4px 15px rgba(238, 90, 111, 0.4);
    padding: 8px 16px;
    font-size: 13px;
}

.btn.logout:hover {
    box-shadow: 0 6px 20px rgba(238, 90, 111, 0.6);
}

.btn.manage {
    background: linear-gradient(135deg, #00c6ff 0%, #0072ff 100%);
    box-shadow: 0 4px 15px rgba(0, 114, 255, 0.4);
}

.btn.manage:hover {
    box-shadow: 0 6px 20px rgba(0, 114, 255, 0.6);
}

.btn {
    display: inline-block;
    padding: 12px 24px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    text-decoration: none;
    border-radius: 8px;
    font-weight: 600;
    transition: all 0.3s ease;
    border: none;
    cursor: pointer;
    font-size: 14px;
    box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
}

.btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
}

.btn.edit {
    background: linear-gradient(135deg, #2196F3 0%, #21CBF3 100%);
    box-shadow: 0 4px 15px rgba(33, 150, 243, 0.4);
    margin-right: 8px;
}

.btn.edit:hover {
    box-shadow: 0 6px 20px rgba(33, 150, 243, 0.6);
}

.btn.delete {
    background: linear-gradient(135deg, #f44336 0%, #e91e63 100%);
    box-shadow: 0 4px 15px rgba(244, 67, 54, 0.4);
}

.btn.delete:hover {
    box-shadow: 0 6px 20px rgba(244, 67, 54, 0.6);
}

table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
    background: white;
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

thead {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
}

th {
    padding: 15px;
    text-align: left;
    font-weight: 600;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

td {
    padding: 15px;
    border-bottom: 1px solid #f0f0f0;
}

tbody tr {
    transition: background-color 0.2s ease;
}

tbody tr:hover {
    background-color: #f8f9ff;
}

tbody tr:last-child td {
    border-bottom: none;
}

.form-container {
    max-width: 600px;
    margin: 30px auto;
    background: #f8f9ff;
    padding: 30px;
    border-radius: 12px;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
}

form {
    display: flex;
    flex-direction: column;
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
input[type="number"],
input[type="date"] {
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
input[type="number"]:focus,
input[type="date"]:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

button[type="submit"] {
    background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
    color: white;
    padding: 14px 28px;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    margin-top: 10px;
    box-shadow: 0 4px 15px rgba(76, 175, 80, 0.4);
    width: 100%;
}

button[type="submit"]:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(76, 175, 80, 0.6);
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

.back-btn {
    margin-bottom: 20px;
    display: inline-block;
}

.empty-state {
    text-align: center;
    padding: 60px 20px;
    color: #999;
}

.empty-state h3 {
    font-size: 1.5em;
    margin-bottom: 10px;
    color: #667eea;
}

td .btn {
    padding: 8px 16px;
    font-size: 12px;
    margin: 0 4px;
}

@media (max-width: 768px) {
    body {
        padding: 10px;
    }
    
    .container {
        padding: 20px;
    }
    
    h1 {
        font-size: 2em;
    }
    
    h2 {
        font-size: 1.5em;
    }
    
    .header {
        flex-direction: column;
        align-items: flex-start;
        gap: 15px;
    }
    
    table {
        font-size: 14px;
    }
    
    th, td {
        padding: 10px 8px;
    }
    
    .btn {
        padding: 10px 16px;
        font-size: 12px;
    }
    
    .form-container {
        padding: 20px;
    }
}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Edit Medicine</h2>
            <div class="user-info">
                <span>👤 <?= htmlspecialchars($currentUser['full_name']) ?> (<?= htmlspecialchars($currentUser['username']) ?>)</span>
                <span class="role-pill"><?= strtoupper(htmlspecialchars($currentUser['role'])) ?></span>
                <?php if ($currentUser['role'] === 'doctor'): ?>
                    <a href="user_management.php" class="btn manage">⚙️ Manage Users</a>
                <?php endif; ?>
                <a href="logout.php" class="btn logout">🚪 Logout</a>
            </div>
        </div>
        
        <div class="back-btn">
            <a href="Pharmacy.PHP" class="btn">← Back to List</a>
        </div>

        <?php if(isset($error)): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <div class="form-container">
            <form method="POST">
                <div class="form-group">
                    <label for="medicine_name">Medicine Name *</label>
                    <input type="text" id="medicine_name" name="medicine_name" value="<?= htmlspecialchars($data['medicine_name']) ?>" placeholder="Enter medicine name" required>
                </div>

                <div class="form-group">
                    <label for="category">Category *</label>
                    <input type="text" id="category" name="category" value="<?= htmlspecialchars($data['category']) ?>" placeholder="e.g., Antibiotic, Painkiller" required>
                </div>

                <div class="form-group">
                    <label for="quantity">Quantity *</label>
                    <input type="number" id="quantity" name="quantity" value="<?= htmlspecialchars($data['quantity']) ?>" placeholder="Enter quantity" min="0" required>
                </div>

                <div class="form-group">
                    <label for="price">Price (Rwf) *</label>
                    <input type="text" id="price" name="price" value="<?= htmlspecialchars($data['price']) ?>" placeholder="Enter price" required>
                </div>

                <div class="form-group">
                    <label for="expiry_date">Expiry Date *</label>
                    <input type="date" id="expiry_date" name="expiry_date" value="<?= htmlspecialchars($data['expiry_date']) ?>" required>
                </div>

                <div class="form-group">
                    <label for="supplier">Supplier *</label>
                    <input type="text" id="supplier" name="supplier" value="<?= htmlspecialchars($data['supplier']) ?>" placeholder="Enter supplier name" required>
                </div>

                <button type="submit" name="update">💾 Update Medicine</button>
            </form>
        </div>
    </div>
</body>
</html>
<?php
    }
}
?>


