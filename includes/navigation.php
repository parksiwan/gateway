<nav class="navbar navbar-inverse navbar-static-top">
<div class="container-fluid">
  <div class="navbar-header">
    <a class="navbar-brand">
      MyWiFi Admin
    </a>
    <form class="navbar-form navbar-left" role="search" method="get" action="search.php">
      <div class="form-group">
        <?php 
        if($_GET["search"]) {  
            $searchvalue = $_GET["search"];
        }
        ?>
        <input type="text" name="search" class="form-control" placeholder="search" value="<?php echo $searchvalue; ?>">
      </div>
      <button type="submit" class="btn btn-default">
         <span class="glyphicon glyphicon-search"></span>
      </button>
    </form>
    <?php
    // print user name if logged in
    if ($_SESSION["username"]) {
        echo "<p class=\"navbar-text\">" . $_SESSION["username"] . "</p>";
    }
    ?>
    <button class="navbar-toggle" data-toggle="collapse" data-target="#main-nav">
      <span class="icon-bar"></span>
      <span class="icon-bar"></span>
      <span class="icon-bar"></span>
    </button>
  </div>
  <div class="collapse navbar-collapse" id="main-nav">
    <!--<ul class="nav navbar-nav navbar-right">-->
    <!--  <li class="active"><a href="index.php">Home</a></li>-->
    <!--  <li><a href="register.php">Register</a></li>-->
    <!--  <li><a href="login.php">Login</a></li>-->
    <!--  <li><a href="logout.php">Logout</a></li>-->
    <!--  <li><a href="news.php">News</a></li>-->
    <!--  <li><a href="/phpmyadmin" target="_blank">Database</a></li>-->
    <!--</ul>-->
    <?php
    $nav = new Navigation();
    echo $nav->getNavigation();
    ?>
  </div>
</div>
</nav>