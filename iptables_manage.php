<?php
session_start();
include("autoloader.php");


$iptables = new Iptables('', '', 0, '', 1);
$iptables_list = $iptables->getAllIptables();

?>

<!doctype html>
<html>
    <?php include("includes/head.php"); ?>
    <body>
        <script>
          window.fbAsyncInit = function() {
            FB.init({
              appId      : '389700194801084',
              cookie     : true,
              xfbml      : true,
              version    : 'v2.11'
            });
              
            FB.AppEvents.logPageView();   
              
          };
        
          (function(d, s, id){
             var js, fjs = d.getElementsByTagName(s)[0];
             if (d.getElementById(id)) {return;}
             js = d.createElement(s); js.id = id;
             js.src = "https://connect.facebook.net/en_US/sdk.js";
             fjs.parentNode.insertBefore(js, fjs);
           }(document, 'script', 'facebook-jssdk'));
        </script>
        <?php include("includes/navigation.php"); ?>
        <div class="container">
            <div class="row">
              <main class="col-md-12">
                  <!-- products -->
                  <h3>Active Internet Usage</h3>
                  <?php
                  if (count($iptables_list) > 0) 
                  {
                      echo "<table class=\"table table-hover\">";
                      echo "<thead><tr><th>Account</th><th>IP address</th>
                            <th>Download Usage</th><th>MAC address</th><th>Internet Package</th><th>Start time</th></tr></thead>";
                      echo "<tbody>";
                      foreach ($iptables_list as $ipt) 
		      {
                          echo "<tr>";
                          $id = $ipt["account_id"];
                          $ip_address = $ipt["ip_address"];
                          $bytes = $ipt["bytes"];
			  $mac_address = $ipt["mac_address"];
			  $internet_package = $ipt["internet_package"];
                          $time = $ipt["start_date_time"];
                          echo "<td><div class=\"col-md-2\">$id</div></td>";
                          echo "<td><div class=\"col-md-2\">$ip_address</div></td>";
                          echo "<td><div class=\"col-md-2\">$bytes</div></td>";
                          echo "<td><div class=\"col-md-2\">$mac_address</div></td>";
                          echo "<td><div class=\"col-md-2\">$internet_package</div></td>";
                          echo "<td><div class=\"col-md-2\">$time</div></td>";
                          echo "</tr>";
                      }
                      echo "</tbody>";
                      echo "</table>";
                  }
                  ?>
              </main>
            </div>
        </div>
        <footer class="container-fluid text-center">
        	<p>Powered By AIT Communication 2017</p>
        </footer>
    </body>
</html>
