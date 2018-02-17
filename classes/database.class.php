<?php
class Database 
{
    protected $connection;
    protected function __construct() 
    {
        // get environment variable
        $host = "localhost";
        $user = "root";
        $password = "psw1101714";
        $database = "gateway";
        // create a connection
        $this->connection = mysqli_connect($host, $user, $password, $database);
    }
    protected function getConnection() 
    {
        return $this->connection;
    }
}
?>
