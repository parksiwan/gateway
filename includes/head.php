<head>
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <link rel="stylesheet" href="components/bootstrap/dist/css/bootstrap.css">
      <link rel="stylesheet" href="components/font-awesome/css/font-awesome.css">
      <link rel="stylesheet" href="mystyle.css">
      <script src="components/jquery/dist/jquery.js"></script>
      <script src="components/bootstrap/dist/js/bootstrap.js"></script>
      <script src="script.js"></script>
      <?php $page_title = basename($_SERVER["PHP_SELF"]); ?>
      <title><?php echo $page_title; ?></title>
      <style>    
            /* Set black background color, white text and some padding */
            footer {
              background-color: #555;
              color: white;
              padding: 15px;
            }
        	header {
        		display: flex;
        		flex-direction: row;
        		justify-content: space-between;
        		padding: 5px 5px 5px 5px;
        		background : linear-gradient(to left,#6DAB69, #DAF7D9);
        		background : cover no-repeat; 
        	}
        	login_div {
        		text-align: left;
        	}
        	lbl {
        		display: inline-block;
        	}
        </style>
</head>


        