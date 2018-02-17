<?php
class Navigation {
    private $logged_in;
    private $current_page;
    
    public function __construct() {
        // check session to see if user is logged in
        if ( isset($_SESSION["account_id"])) {
            $this->logged_in = true;
        } else {
            $this->logged_in = false;
        }
        // get the name of the current page
        $this->current_page = $_SERVER["PHP_SELF"];
    }
    
    public function getNavigation() {
        $nav_array = array();
        if ($this->logged_in == false) {
            $nav_items = array(); 
        } else {
            $nav_items = array(); 
        }
        // add the ul element to nav_array
        array_push($nav_array, "<ul class=\"nav navbar-nav navbar-right\">");
        foreach ($nav_items as $name=>$link) {
            if ($link == $this->current_page) {
                $class = "class=\"active\"";
            } else {
                $class = "";
            }
            $element = "<li $class><a href=\"$link\">$name</a></li>";
            array_push($nav_array, $element);
        }
        // add </ul> at the end of array
        array_push($nav_array, "</ul>");
        return implode($nav_array, ""); //convert array into string
    }
}
?>
