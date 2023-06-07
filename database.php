<?php
$server = '127.0.0.1:33065';
$username = 'root';
$password = '';
$database = 'php_login_database';

try {
  $conn = new PDO("mysql:host=$server;dbname=$database;", $username, $password);
  global $pdo;
} catch (PDOException $e) 

  {
    die('Connection Failed: ' . $e->getMessage());
  }

?>