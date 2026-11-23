<?php
// The shop of range one: one page that keeps a session and asks the database
// for its items. The database's address, account and password are in
// config.php, which the spec plants beside this file.
session_start();
$_SESSION['views'] = ($_SESSION['views'] ?? 0) + 1;
include __DIR__ . '/config.php';

mysqli_report(MYSQLI_REPORT_OFF);
$db = @new mysqli($db_host, $db_user, $db_password, 'shop');
if ($db->connect_errno) {
    http_response_code(503);
    echo "database error\n";
    exit;
}
$item = isset($_GET['item']) ? (int) $_GET['item'] : 0;
$query = $db->prepare('SELECT id, name, price FROM items WHERE ? = 0 OR id = ? ORDER BY id');
$query->bind_param('ii', $item, $item);
$query->execute();
$rows = $query->get_result()->fetch_all(MYSQLI_ASSOC);
?>
<!doctype html>
<title>Shop</title>
<h1>Shop</h1>
<p><?= count($rows) ?> items in stock</p>
<ul>
<?php foreach ($rows as $row): ?>
  <li><a href="/?item=<?= (int) $row['id'] ?>"><?= htmlspecialchars($row['name']) ?></a>, <?= htmlspecialchars($row['price']) ?></li>
<?php endforeach; ?>
</ul>
