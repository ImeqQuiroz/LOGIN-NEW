<?php
session_start();

if (!isset($_SESSION['countdown'])) {
  $_SESSION['countdown'] = time() + 60; // Establecer la marca de tiempo actual + 60 segundos
}

if ($_SESSION['countdown'] > time()) {
  $remainingTime = $_SESSION['countdown'] - time(); // Calcular el tiempo restante
  
} else {
  unset($_SESSION['countdown']); // Limpiar la sesión
  header('Location: login.php'); // Redirigir a la página de inicio de sesión si el tiempo ha alcanzado cero
  exit();
}
?>

<!DOCTYPE html>
<html>
<head>

  <meta charset="utf-8">
  <title>Bloqueado</title>
  <center>
  <img  src="../php-login-simple-master/esperanding.jpg" ></center>

  <script>
  window.onload = function() {
    var countdown = <?php echo isset($remainingTime) ? $remainingTime : 0; ?>;

    function updateCountdown() {
      if (countdown > 0) {
        countdown--;
        document.getElementById('countdown').textContent = countdown; // Actualizar el contador en la página
        setTimeout(updateCountdown, 1000); // Actualizar cada segundo
      } else {
        window.location.href = 'login.php'; // Redirigir a la página de inicio de sesión una vez que el tiempo haya alcanzado cero
      }
    }

    updateCountdown();

    // Bloquear la navegación hacia atrás
    window.history.pushState(null, '', window.location.href);
    window.onpopstate = function() {
      window.history.pushState(null, '', window.location.href);
    };
  };
</script>
</head>
<body>
  <center><h1>Usted está bloqueado</h1>
  
  <p>Por favor, espere <span id="countdown"><?php echo isset($remainingTime) ? $remainingTime : 0; ?></span> segundos mientras permanece en esta página.</p>

  </center>
</body>
</html>





