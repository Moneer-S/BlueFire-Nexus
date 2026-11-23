<?php
// The shop's cache job: writes the items to /tmp/shop-cache-<minute>.json and
// removes the files of earlier minutes. The range's ordinary activity runs it
// once a minute as www-data.
include __DIR__ . '/config.php';

mysqli_report(MYSQLI_REPORT_OFF);
$db = @new mysqli($db_host, $db_user, $db_password, 'shop');
if ($db->connect_errno) {
    fwrite(STDERR, "database error\n");
    exit(1);
}
$rows = $db->query('SELECT id, name, price FROM items ORDER BY id')->fetch_all(MYSQLI_ASSOC);
$file = '/tmp/shop-cache-' . date('YmdHi') . '.json';
file_put_contents($file, json_encode($rows) . "\n");
foreach (glob('/tmp/shop-cache-*.json') as $old) {
    if ($old !== $file) {
        unlink($old);
    }
}
