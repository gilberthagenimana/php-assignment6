<?php
if (isset($_POST['save'])) {
    $name = $_POST['name'];
    $email = $_POST['email'];
    $conn->query("INSERT INTO users (name, email) VALUES ('$name', '$email')");
    header("Location: etude.php");
    exit();
}
// ==== UPDATE DATA ====
if (isset($_POST['update'])) {
    $id = $_POST['id'];
    $name = $_POST['name'];
    $email = $_POST['email'];
    $conn->query("UPDATE users SET name='$name', email='$email' WHERE id=$id"); 
    header("Location: etude.php"); 
    exit();
}
        <button type="submit" name="save">Save</button>
        <?php else: ?>
        <button type="submit" name="update">Update</button>
        <?php endif; ?>
    </form>
</body>
</html>
<?php   
}
?>
    <?php endif;
}   
// ==== DELETE DATA ====
if (isset($_GET['delete'])) {
    $id = $_GET['delete'];
    $conn->query("DELETE FROM users WHERE id=$id");

    header("Location: etude.php");
    exit();
}
// ==== EDIT DATA (FETCH ONE RECORD) ====
$edit_state = false;        
$name = "";
$email = "";
$id = 0;
if (isset($_GET['edit'])) {
    $id = $_GET['edit'];
    $result = $conn->query("SELECT * FROM users WHERE id=$id");
    $row = $result->fetch_assoc();
    $name = $row['name'];
    $email = $row['email'];
    $edit_state = true;
}
<?php
if (isset($_POST['save'])) {
    $name = $_POST['name'];
    $email = $_POST['email];;
    $conn->query("INSERT INTO users (name, email) VALUES ('$name', '$email')");
    header("Location: etude.php");
    exit();
}
// ==== UPDATE DATA ====
if (isset($_POST['update'])) {
    $id = $_POST['id'];
    $name = $_POST['name'];
    $email = $_POST['email'];
    $conn->query("UPDATE users SET name='$name', email='$email' WHERE id=$id"); 
    header("Location: etude.php"); 
    exit();
}   
// ==== DELETE DATA ====
if (isset($_GET['delete'])) {   
    $id = $_GET['delete'];
    $conn->query("DELETE FROM users WHERE id=$id");
    header("Location: etude.php");
    exit();
}
// ==== EDIT DATA (FETCH ONE RECORD) ====
$edit_state = false;        
$name = "";
$email = "";
$id = 0;
if (isset($_GET['edit'])) {
    $id = $_GET['edit   ];
    $result = $conn->query("SELECT * FROM users WHERE id=$id");
    $row = $result->fetch_assoc();
    $name = $row['name'];       
    $email = $row['email'];
    $edit_state = true;
}
<!DOCTYPE html>
<html>      
<head>
    <title>Simple PHP CRUD</title>
</head>
<body>
    <b><h2>Simple CRUD in PHP</h2></b>
    <!-- ==== FORM SECTION ==== -->
    <form method="POST" action="etude.php">
        <input type="hidden" name="id" value="<?= $id; ?>">
        <label>Name:</label>
        <input type="text" name="name" value="<?= $name; ?>" required><br><br>
        <label>Email:</label>
        <input type="email" name="email" value="<?= $email; ?>" required><br><br>
        <?php if ($edit_state == false): ?>
            <button type="submit" name="save">Save</button>
        <?php else: ?>
            <button type="submit" name="update">Update</button>
        <?php endif; ?>
    </form>
    <hr>    
    <!-- ==== DISPLAY DATA SECTION ==== -->
    <table border="1" cellpadding="10">
        <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Email</th>
            <th>Action</th>
        </tr>
        <?php
        $results = $conn->query("SELECT * FROM users");
        while ($row = $results->fetch_assoc()) {  
?>