<?php
session_start();

require 'database.php';
require 'log.php';
if (isset($_SESSION['countdown']) && $_SESSION['countdown'] > time()) {
    header('Location: blocked.php'); // Redirigir a la página de bloqueo si el usuario aún está bloqueado
    exit();
  }//PARA LO DEL DIRECCION DEL BLOQUEO BROTHER


if (!isset($_SESSION['user_id'])) {
    // verifica si se tiene secion activa redirige
    header("Location: index.php");
    exit();
} else {
    $records = $conn->prepare('SELECT name, email, password, rol FROM users WHERE id = :id');
    $records->bindParam(':id', $_SESSION['user_id']);
    $records->execute();
    $results = $records->fetch(PDO::FETCH_ASSOC);

    if (!is_array($results) || count($results) === 0 || $results['rol'] !== 'admin') {
        // El usuario no es un administrador, redirigir a la página de inicio
        header("Location: index.php");
        exit();
    }
}
?>

<!DOCTYPE html>
<html>

<head>
    <title>Panel de Administración</title>
    <style>
        /* Estilos CSS para la apariencia */
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
        }
        
        header {
            background-color: #333;
            color: #fff;
            padding: 20px;
            text-align: center;
        }
        
        nav {
            background-color: #f1f1f1;
            padding: 10px;
        }
        
        nav ul {
            list-style-type: none;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
        }
        
        nav ul li {
            margin-right: 10px;
        }
        
        section {
            margin: 20px;
        }
        
        footer {
            background-color: #333;
            color: #fff;
            padding: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <header>
        <h1>Panel de Administración</h1>
        <a href="logout.php">Cerrar sesión</a>
    </header>
    
    <footer>
        &copy; <?php echo date('Y'); ?> Todos los derechos reservados.
    </footer>
</body>
</html>