<?php
include("autoloader.php");

/* require the mac as the parameter */
if(isset($_GET['account_id']) && isset($_GET['internet_package']) && isset($_GET['mac_address']))
{
    //$number_of_posts = isset($_GET['num']) ? intval($_GET['num']) : 10; //10 is the default
    $mac_address = strval($_GET['mac_address']);
    $internet_package = intval($_GET['internet_package']);
    $account_id = intval($_GET['account_id']);
    
    $ip_table = new Iptables($mac_address, '', $account_id, 0, $internet_package);

    if ($ip_table->findMacAddressInMacList() && $ip_table->findMacAddressInIptables())
    {
        $ip_table->updateAccountIdInIpTables();
        $ip_table->updateAccountIdInMacList();
    }
}
?>
