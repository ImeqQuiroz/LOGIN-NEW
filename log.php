<?php
require_once "database.php"; 
  
function guardar_registro($email, $error, $validation ,$intentos=0) {
    global $conn;
    
    $estado = $error ? "FALLO" : "EXITO";
    $fecha_hora = date('Y-m-d H:i:s');
    $IP = $_SERVER['REMOTE_ADDR'];
    $navegador = $_SERVER['HTTP_USER_AGENT'];
    $sistema_operativo = php_uname('s') . ' ' . php_uname('r');
    //$log = "$estado|$fecha_hora|$email|$ip|$navegador|$sistema_operativo|$validation\n";
    // Insertar registro en la base de datos
    $stmt = $conn->prepare("INSERT INTO registro (fecha_hora, email, IP, estado,  navegador, sistema_operativo, validation, intentos) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    //$stmt->execute([$estado, $fecha_hora, $email, $ip, $navegador, $sistema_operativo]);
    $stmt->execute([$fecha_hora, $email, $IP, $estado, $navegador, $sistema_operativo, $validation, $intentos]);
   
    

    // Escribir registro en archivo log.txt
    //file_put_contents('log.txt', $log, FILE_APPEND);
}

?>