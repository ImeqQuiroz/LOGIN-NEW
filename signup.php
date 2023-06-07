<?php
session_start();

require 'database.php';

$message = '';
$error_message = '';

if (isset($_SESSION['countdown']) && $_SESSION['countdown'] > time()) {
  header('Location: blocked.php');
  exit();
}

if (!isset($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (!empty($_POST['email']) && !empty($_POST['password']) && !empty($_POST['name']) && !empty($_POST['confirm_password'])) {
  if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    $error_message = 'Token CSRF no válido.';
  } else {
    // Validar los datos de entrada
    $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
    if (!$email) {
      $error_message = 'Ingrese un correo electrónico válido.';
    } else {
      $password = $_POST['password'];
      $name = $_POST['name'];
      $confirm_password = $_POST['confirm_password'];

      if ($password !== $confirm_password) {
        $error_message = 'Las contraseñas no coinciden.';
      } else {
        // Limitar la longitud de entrada
        $email = substr($email, 0, 100); // Limita el campo "email"
        $password = substr($password, 0, 10); // Limita el campo "password"
        $name = substr($name, 0, 20); // Limita el campo "name"

        $sql = "INSERT INTO users (email, password, name) VALUES (:email, :password, :name)";
        $stmt = $conn->prepare($sql);

        $stmt->bindParam(':email', $email);
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);
        $stmt->bindParam(':password', $hashed_password);
        $stmt->bindParam(':name', $name);

        if ($stmt->execute()) {
          $user_id = $conn->lastInsertId(); // Obtener el ID del usuario recién creado

          // Asignar el rol de usuario por defecto al nuevo usuario
          $default_role = 'user';
          $update_role = $conn->prepare('UPDATE users SET rol=:rol WHERE id=:id');
          $update_role->bindParam(':rol', $default_role);
          $update_role->bindParam(':id', $user_id);
          $update_role->execute();

          $message = 'Usuario creado exitosamente';
        } else {
          $message = 'Lo sentimos, hubo un error al crear la cuenta. Vuelve a intentarlo';
        }
      }
    }
  }
}
?>

<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Registrate</title>
  <link href="https://fonts.googleapis.com/css?family=Roboto" rel="stylesheet">
  <link rel="stylesheet" href="assets/css/style.css">
  <script>
    // Evitar ejecución de código inline en el documento HTML
    document.addEventListener('DOMContentLoaded', function() {
      var scriptElements = document.getElementsByTagName('script');
      for (var i = 0; i < scriptElements.length; i++) {
        var scriptSrc = scriptElements[i].getAttribute('src');
        if (scriptSrc !== 'https://www.google.com/recaptcha/api.js') {
          scriptElements[i].removeAttribute('src');
        }
      }
    });

    // Bloquear carga de recursos desde dominios no confiables
    var imgElements = document.getElementsByTagName('img');
    for (var i = 0; i < imgElements.length; i++) {
      var imgSrc = imgElements[i].src;
      if (!imgSrc.startsWith('https://www.google.com/recaptcha/api.js')) {
        imgElements[i].src = ''; // O eliminar el elemento img completamente
      }
    }
  </script>
</head>
<body>
  <?php require 'partials/header.php' ?>

  <?php if (!empty($message)): ?>
    <p><?= $message ?></p>
  <?php endif; ?>

  <h1>Crear Cuenta</h1>
  <span>o <a href="login.php">Ingresar</a></span>
  
  <?php if (!empty($error_message)): ?>
    <p class="error"><?php echo $error_message; ?></p>
  <?php endif; ?>
  
  <form action="signup.php" method="POST">
    <input name="name" type="text" placeholder="Ingrese un nombre">
    <input name="email" type="text" placeholder="Ingresar correo electrónico">
    <input name="password" type="password" placeholder="Ingrese una contraseña">
    <input name="confirm_password" type="password" placeholder="Confirme la contraseña">
    
    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
    <input type="submit" value="Enviar">
  </form>
</body>
</html>
