<?php
class Iptables extends Database
{
    private $_mac_address;
    private $_ip_address;
    private $_account_id;
    private $_bytes;
    private $_internet_package;

    public function __construct($mac_address, $ip_address, $account_id, $bytes, $internet_package)
    {
        parent::__construct();    // call the parent's construct method
        $this->_mac_address = $mac_address;
        $this->_ip_address = $ip_address;
        $this->_account_id = $account_id;
        $this->_bytes = $bytes;
        $this->_internet_package = $internet_package;
    }

    public function getAllIptables()
    {
        $query = "SELECT account_id, ip_address, bytes, mac_address, internet_package, start_date_time from iptables where account_id > 0 order by account_id"; 
	$statement = $this->connection->prepare($query);
	if ($statement->execute())
	{
	    $result = $statement->get_result();
	    if ($result->num_rows > 0)
	    {
		$iptables = array();
		while ($row = $result->fetch_assoc())
		{
		    array_push($iptables, $row);
		}
                return $iptables;
            }
	    else
	    {
	        return false;
	    }
	}
	else
	{
	    return false;
	}
    }

    public function findMacAddressInMacList()
    {
        $query = "select account_id from iptables where mac_address = ?";
        $statement = $this->connection->prepare($query);
        $statement->bind_param("s", $this->_mac_address);

        if ($statement->execute())
        {
            $result = $statement->get_result();
            if ($result->num_rows > 0)    // check number of rows in result
	    {
                return $true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            return false;
        }
    }

    public function findMacAddressInIptables()
    {
        $query = "select account_id from mac_list where mac_address = ?";
	$statement = $this->connection->prepare($query);
        $statement->bind_param("s", $this->_mac_address);
	if ($statement->execute())
	{
	    $result = $statement->get_result();
	    if ($result->num_rows > 0)
            {
                return true;
	    }
	    else
	    {
                return false;
	    }
	}
        else
	{
	    return false;
	}
    }


    public function updateAccountIdInIpTables()
    {
      $query = "UPDATE iptables SET account_id = ?, internet_package = ?, bytes = 0 WHERE mac_address = ?";
      $statement = $this->connection->prepare($query);
      $statement->bind_param("iis", $this->_account_id, $this->_internet_package, $this->_mac_address);

      if ($statement->execute())
      {
          //account has been created
          $this->_message["type"] = "success";
          $this->_message["text"] = "Your account has been updated.";
          return true;
      }
      else
      {
          $this->_message["type"] = "danger";
          $this->_message["text"] = "Update error.";
          return false;
      }
    }


    public function updateAccountIdInMacList()
    {
        $query = "UPDATE mac_list SET account_id = ?, active = 1  WHERE mac_address = ?";
        $statement = $this->connection->prepare($query);
        $statement->bind_param("is", $this->_account_id, $this->_mac_address);

        if ($statement->execute())
        {
            //account has been created
            $this->_message["type"] = "success";
            $this->_message["text"] = "Your account has been updated.";
            return true;
        }
        else
        {
            $this->_message["type"] = "danger";
            $this->_message["text"] = "Update error.";
            return false;
        }
    }

}
?>
