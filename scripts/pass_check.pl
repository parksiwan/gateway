#!/usr/bin/perl -w
use DBI();
use strict;

use CGI qw(-no_debug :standard);
my $cgi_object = new CGI;
# debug settings
my $debug_to_web=0;
my $debug_to_logfile=1;
my $debug_to_stdout=0;
#
my ($visit_id, $casual_id, $room_id, $mb_limit);
my $db_name = vod_global_cfg('menu_db_name');
my $db_user = vod_global_cfg('db_user');
my $db_pass = vod_global_cfg('db_pass');
my $dbh=DBI->connect("DBI:mysql:database=" . $db_name . ";host=localhost", $db_user, $db_pass, {'RaiseError' => 1});

$ENV{'PATH'} = "/bin:/usr/bin";

my $web_ip = get_attribute("web_server_ip");
my $return_page = "http://$web_ip/hotel/inet_pass_ask.php";
my $max_wireless_users_per_ip = 6; # changed from 10->6 on 19/6/12
my $max_wired_users_per_ip    = 6; # added 18/7/12

open(LOG, ">> /var/log/pass_check.log");

check_stoperrors();

print $cgi_object->header,
	  $cgi_object->start_html(-title => 'Pass Check',
							  -style => {'src'=>'/hotel/css/pass_check_pl.css'} );
print "<br>\r\n";

my $free_lobby = 0;

if ($cgi_object->param())
{
	my $real_ip=0;
	if ($ENV{'HTTP_X_FORWARDED_FOR'})
	{
		$real_ip = $ENV{'HTTP_X_FORWARDED_FOR'};
	}
	else
	{
		$real_ip = $ENV{'REMOTE_ADDR'};
	}
	my $ip = $cgi_object->param('ip_address');

	if (!$real_ip && $ip)
	{
		debug("Supplied IP $ip may be forged. Could not determine remote IP address.", "WARN");
	}

	if ($real_ip && !$ip)
	{
		debug("No IP supplied but will use detected remote IP $real_ip", "WARN");
		$ip = $real_ip;
	}

	if ($real_ip && $ip)
	{
		if ($real_ip ne $ip)
		{
			debug("Supplied IP $ip may be forged. Will use detected remote IP $real_ip", "WARN");
		}
		$ip = $real_ip;
	}

	# untaint IP..
	if ($ip =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
	{
		$ip = $1
	}
	else
	{
		debug("IP: $ip not in right format, possible hack attempt - exit", "ERROR");
		exit(10);
	}

	my $mac = `/usr/bin/getdhcp_mac.pl $ip`;
	$mac =~ s/\n//;

	my $static_ip_detected = 0;
	if (!$mac)
	{
		debug("Could not find MAC for ip: $ip, possibly a static IP being used", "ERROR");
		$static_ip_detected = 1;
	}
	else
	{
		debug("Found MAC: $mac in DHCP leases for IP: $ip");
	}

	$free_lobby = $cgi_object->param('lobby') if defined($cgi_object->param('lobby'));

	my $pass = $cgi_object->param('password_submit');
	my $form_client_type = $cgi_object->param('client_type');
	if ($form_client_type)
	{
		$return_page .= "?dept=login_screen&type=$form_client_type";
	}

	if ($pass ne '' && $ip ne '') # found password and ip
	{
		my $pass_accept=0;
		debug("Initializing Access Request for IP $ip, PASS: '$pass'");

		my ($access_id, $client_type) = does_password_exist($pass);
		if ($access_id && $client_type && !$static_ip_detected) # password OK
		{
			debug("Password accepted for IP $ip, PASS '$pass'. Access ID: $access_id, type: $client_type");

			my $active_rowcount = is_access_activated($access_id, $client_type);
			if ($active_rowcount > 0)
			{
				########################################
				#
				# EXISTING (secondary) activation - new IP for existing password
				#
				########################################

				debug("Access has been previously activated $active_rowcount time(s) for PASS: '$pass'.");

				# get wireless clients (10.20.x.x)
				my $active_wireless_rowcount = is_access_activated_wireless($access_id, $client_type);

				# get wired clients (10.0.x.x)
				my $active_wired_rowcount = is_access_activated_wired($access_id, $client_type);

				my $ref = get_access_data($access_id, $client_type);

				$room_id              = $ref->{'room_id'};
				$visit_id             = $ref->{'visit_id'};
				$casual_id            = $ref->{'casual_id'};
				$mb_limit             = $ref->{'mb_limit'};
                                      
				my $sdt               = $ref->{'start_date_time'};
				my $edt               = $ref->{'end_date_time'};
				my $entered_dt        = $ref->{'entered_date_time'};
				my $deal_id           = $ref->{'internet_deal_id'};
				my $deal_max_wired    = $ref->{'deal_max_wired'};
				my $deal_max_wireless = $ref->{'deal_max_wireless'};
				my $user_max_wired    = $ref->{'user_max_wired'};
				my $user_max_wireless = $ref->{'user_max_wireless'};

				if (!duplicate_ip($ip, $pass) && $active_wireless_rowcount < $max_wireless_users_per_ip && $active_wired_rowcount < $max_wired_users_per_ip)
				{
					debug("new IP $ip for the PASS '$pass' account will be added to access_list table");
					my $stoperror = 0;

					# duplicating access list row for new $ip same pass.
					my $ins_sql0 = "INSERT INTO access_list
									(room_id,visit_id,casual_id,password,ip_address,start_date_time,end_date_time,entered_date_time,mb_limit,internet_deal_id,active)
									 VALUES
									('$room_id','$visit_id','$casual_id','$pass','$ip','$sdt','$edt','$entered_dt','$mb_limit','$deal_id','Y')";
					eval { $dbh->do($ins_sql0); };
					if ($@)
					{
						debug("access_list secondary INSERT failed for IP $ip, PASS: '$pass', access_id $access_id, type: $client_type (reason: " . $@ . ") SQL: '$ins_sql0'");
						$stoperror = 11;
					}
					else
					{
						debug("access_list secondary INSERT OK for IP $ip, PASS: '$pass', access_id $access_id, type: $client_type.");
					}

					if (!$stoperror)
					{
						if (iptables_sys_insert($ip))
						{
							debug("iptables system inserts OK, now inserting iptables DB entries");
							iptables_db_insert($access_id, $client_type, $ip, $room_id);
						}
						else
						{
							$stoperror = 12;
							debug("iptables system inserts failed, not inserting iptables DB entries", "ERROR");
						}
					}

					if (!$stoperror)
					{
						good_login($ip, $pass, 1);
					}
					else
					{
						debug("STOPERROR $stoperror - An Internal error occured.", "ERROR");
						pc_head('error');
						print "An Internal error occured.<br><br>Code: $stoperror<br><br>\r\n";
						print "<a href='" . $return_page . "'>Click Here</a> to try again<br>\r\n";
					}
				}
				else # Either duplicate IP or max wireless users exceeded..
				{
					if ( duplicate_ip($ip, $pass) )
					{
						debug("duplicate ip $ip found in access_list for pass '$pass'. that ip tried to re-activate an active account.", "WARN");
						pc_head('error');
						print "Trying to re-activate an already active account.<br><br>\r\n";
						print "<a href='http://www.google.com/'>Click Here</a> to browse the web<br>\r\n";
					}
					elsif ($active_wireless_rowcount >= $max_wireless_users_per_ip) # max wireless users exceeded
					{
						debug("maximum wireless users ($max_wireless_users_per_ip) reached, cannot authenticate ip: '$ip', pass: '$pass'.", "WARN");
						pc_head('error');
						print "Maximum Wireless users ($max_wireless_users_per_ip) reached.<br><br>\r\n";
						print "<a href='" . $return_page . "'>Click Here</a> to go back<br>\r\n";
					}
					else # max wired users exceeded
					{
						debug("maximum wired users ($max_wired_users_per_ip) reached, cannot authenticate ip: '$ip', pass: '$pass'.", "WARN");
						pc_head('error');
						print "Maximum Wired users ($max_wired_users_per_ip) reached.<br><br>\r\n";
						print "<a href='" . $return_page . "'>Click Here</a> to go back<br>\r\n";
					}
				}
			}
			else # active_rowcount = 0, initial activation.
			{
				########################################
				#
				# Brand new activation section
				#
				########################################

				debug("Initial activation. No previous activations have occured for IP $ip, PASS '$pass'");
				my $stoperror = 0;

				if (my $ref = get_access_data($access_id, $client_type))
				{
					my $description = $ref->{'description'};
					my $deal_price  = $ref->{'price'};
					my $deal_min    = $ref->{'length_min'};
					my $deal_id     = $ref->{'internet_deal_id'};

					$visit_id  = $ref->{'visit_id'};
					$casual_id = $ref->{'casual_id'};
					$room_id   = $ref->{'room_id'};
					$mb_limit  = $ref->{'mb_limit'};

					my $access_type;
					my $mtype;
					if ($client_type eq 'guest')
					{
						$mtype = 'visit_id'; # default for 'guest' or other type
						$access_type = get_access_type($room_id);
					}
					else # room_id will be 0
					{
						$mtype = 'casual_id';
						$access_type = 'norm';
					}

					my $deal_type = $ref->{'type'};
					my $print_deal_type = ucfirst($deal_type);

					if (!$stoperror)
					{
						if ( iptables_sys_insert($ip) )
						{
							debug("iptables system inserts OK, now inserting iptables DB entries");
							iptables_db_insert($access_id, $client_type, $ip, $room_id);
						}
						else
						{
							debug("iptables system inserts failed, not inserting iptables DB entries", "ERROR");
							$stoperror = 3;
						}
					}

					if (!$stoperror)
					{
						my $upd_sql = "UPDATE access_list
										  SET ip_address      = '$ip',
											  start_date_time = now(),
											  end_date_time   = date_add(now(),INTERVAL " . $deal_min . " MINUTE)
									   WHERE $mtype = '$access_id'";
						eval { $dbh->do($upd_sql); };
						if ($@)
						{
							debug("access_list DB UPDATE FAILED. Reason: " . $@, "ERROR");
							debug("access_list SQL: $upd_sql");
							$stoperror = 2;
						}
						else
						{
							debug("access_list DB UPDATE OK");
						}
					}

					my $discount_perc = 0;
					if ($client_type eq 'guest')
					{
						if (!$stoperror)
						{
							my $ins_sql3 = "INSERT INTO internet_deal_session
												(internet_deal_id, visit_id, datetime)
											VALUES
												('$deal_id', '$visit_id', now())";
							eval { $dbh->do($ins_sql3); };
							if ($@)
							{
								debug("internet_deal_session DB INSERT FAILED. Reason: " . $@, "ERROR");
								debug("internet_deal_session SQL: $ins_sql3");
								$stoperror = 5;
							}
							else
							{
								debug("internet_deal_session DB INSERT OK");
							}
						}
						$discount_perc = internet_discount_price($deal_id, $visit_id);
					}

					if (!$stoperror)
					{
						my $ins_sql3 = "INSERT INTO access_list_session
											(ip_address, mac_address, start_date_time, end_date_time)
										VALUES
											('$ip', '$mac', now(), date_add(now(),INTERVAL " . $deal_min . " MINUTE))";
						eval { $dbh->do($ins_sql3); };
						if ($@)
						{
							debug("access_list_session DB INSERT FAILED. Reason: " . $@, "ERROR");
							debug("access_list_session SQL: $ins_sql3");
							$stoperror = 4;
						}
						else
						{
							debug("access_list_session DB INSERT OK");
						}
					}


					if ($discount_perc > 0)
					{
						$deal_price -= ($deal_price * $discount_perc) / 100;
					}

					if (!$stoperror) # No errors yet, lets add expense..
					{
						# Expense (billing) INSERT for initial/primary IP address
						debug("Inserting expense for primary_ip access");
						my $ins_sql1 = "INSERT INTO expense (expense, cat, cost, date_time, end_date_time, access_type, " . $mtype . ")
										VALUES ('$description','$print_deal_type Internet','$deal_price',now(), date_add(now(),INTERVAL " . $deal_min . " MINUTE),'$access_type','$access_id')";

						my $expense_id = 0;
						eval {
							$dbh->do($ins_sql1);
							$expense_id = $dbh->{'mysql_insertid'};
						};
						if ($@)
						{
							debug("expense1 db INSERT: FAILED. Reason: " . $@, "ERROR");
							debug("expense1 SQL: $ins_sql1");
							$stoperror=1;
						}

						if (!$stoperror) # Expense inserted OK, lets add PMS entry
						{
							# PMS Request INSERT
							if ($access_type eq 'norm' && $client_type eq 'guest')
							{
								my $charge_type_internet = get_attribute('charge_type_internet');
								if (!$charge_type_internet)
								{
									$charge_type_internet = "99";
								}

								my $ins_sql2 = "INSERT INTO pms_request (pms_req_type,reference_code,room_no,description,charge,pms_processed,pms_req_active,retry_count,expense_id)
												VALUES ('8','$charge_type_internet','$room_id','$description Internet','$deal_price','N','Y','0','$expense_id')";

								# inserting regardless of pms_type because the pms_request table will be used by other mechanisms to transfer billing data, ie E-mail..
								eval { $dbh->do($ins_sql2); };
								if ($@)
								{
									debug("pms_request DB INSERT: FAILED. Reason: " . $@, "ERROR");
									debug("pms_request sql: $ins_sql2");
									$stoperror=2;
								}
								else
								{
									debug("pms_request DB INSERT OK");
								}
							}
						}
						else # Expense failed to be inserted
						{
							debug("STOPERROR $stoperror - An Internal error occured.", "ERROR");
							pc_head('error');
							print "An Internal error occured.<br><br>Code: $stoperror<br><br>\r\n";
							print "<a href='" . $return_page . "'>Click Here</a> to try again<br>\r\n";
						}

						if (!$stoperror) # No errors yet, login OK
						{
							good_login($ip, $pass, 0);
						}
						else # Expense or PMS inserts failed, no login..
						{
							debug("STOPERROR $stoperror - An Internal error occured.", "ERROR");
							pc_head('error');
							print "An Internal error occured.<br><br>Code: $stoperror<br><br>\r\n";
							print "<a href='" . $return_page . "'>Click Here</a> to try again<br>\r\n";
						}
					}
					else
					{
						debug("STOPERROR $stoperror - An Internal error occured.", "ERROR");
						pc_head('error');
						print "An Internal error occured.<br><br>Code: $stoperror<br><br>\r\n";
						print "<a href='" . $return_page . "'>Click Here</a> to try again<br>\r\n";
					}
				}
				else # could not get access data
				{
					debug("Unable to obtain any access_list row data for access_id $access_id, type: $client_type, Primary IP account WILL FAIL.", "ERROR");
					pc_head('error');
					print "An Internal error occured.<br><br>Code: 4<br><br>\r\n";
					print "<a href='" . $return_page . "'>Click Here</a> to try again<br>\r\n";
				}
			} # end initial activation (rowcount check)
		}
		else # incorrect password OR static IP
		{
			if ($static_ip_detected)
			{
				pc_head('loginfail');
				print "Invalid login details (static IP).<br><br>\r\n";
				print "<a href='" . $return_page . "'>Click Here</a> to try again<br>\r\n";
				debug("Invalid login details detected for IP $ip, PASS '$pass', Static IP Detected!");
			}
			else
			{
				pc_head('loginfail');
				print "Invalid login details.<br><br>\r\n";
				print "<a href='" . $return_page . "'>Click Here</a> to try again<br>\r\n";
				debug("Invalid login details detected for IP $ip, PASS '$pass'");
			}
		}
	}
	else # no password and no ip - ERROR
	{
		if (!$pass && !$ip)
		{
			debug("Password and IP address empty, cannot continue.", "ERROR");
			pc_head('error');
			print "Password and IP address empty, something went wrong.<br><br>\r\n";
			print "<a href='" . $return_page . "'>Click Here</a> to try again<br>\r\n";
		}
		elsif (!$pass && $ip)
		{
			debug("Password empty but IP: $ip OK, cannot continue without submitted password", "ERROR");
			pc_head('error');
			print "Password empty, IP OK, something went wrong.<br><br>\r\n";
			print "<a href='" . $return_page . "'>Click Here</a> to try again<br>\r\n";
		}
		elsif ($pass && !$ip)
		{
			debug("Password found, but IP is empty, cannot continue without valid IP", "ERROR");
			pc_head('error');
			print "Password found, IP empty, something went wrong.<br><br>\r\n";
			print "<a href='" . $return_page . "'>Click Here</a> to try again<br>\r\n";
		}
	} # end pass/ip supplied
}
else # not called from web, or called without any FORM or URL parameters
{
	debug("No form variables found at all, cannot continue.", "ERROR");
	pc_head('error');
	print "No form vars found, something went wrong<br><br>\r\n";
	print "<a href='" . $return_page . "'>Click Here</a> to try again<br>\r\n";
}

print '</td>'."\r\n";
print '</tr>'."\r\n";
print '</table>'."\r\n";

$dbh->disconnect();
close(LOG);
print $cgi_object->end_html() . "\r\n";

#
#
# END MAIN
#
#
#
#
#
#
#
#
#
#
#
# BEGIN SUBS
#
#

sub get_real_net_mask
{
	my $if = shift;
	my $ifc = `/sbin/ifconfig $if`;
	my ($ip, $bcast, $mask);
	if ($ifc =~ /inet\saddr:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*Bcast:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*Mask:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
	{
		$ip    = $1;
		$mask  = $3;

		if ($ip =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/) # needs to be an ip address
		{
			$ip = $1; # $ip now untainted
		}
		else
		{
			debug("get_real_net_mask() - Bad data during untaint of ip $ip", "ERROR");
			return (0, 0);
		}
		if ($mask =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/) # needs to be an ip address
		{
			$mask = $1; # $ip now untainted
		}
		else
		{
			debug("get_real_net_mask() - Bad data during untaint of MASK: $mask", "ERROR");
			return (0, 0);
		}
		if (-f "/etc/mandrake-release")
		{
			my $net = `/bin/ipcalc -n $ip $mask`;
			if ($net =~ /^NETWORK=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
			{
				$net = $1;
				return ($net, $mask);
			}
			else
			{
				return (0, 0);
			}
		}
		else
		{
			my $net = `/usr/bin/ipcalc -b -n $ip $mask`;
			if ($net =~ /Network:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/.*/mi)
			{
				$net = $1;
				return ($net, $mask);
			}
			else
			{
				return (0, 0);
			}
		}
	}
	else
	{
		debug("get_real_net_mask() - 'ifconfig $if' failed", "ERROR");
		return (0, 0);
	}
}

sub pc_head
{
	my $code = shift;
	my $img = 'error.gif'; # default
	if ($code eq 'loginok')   { $img = 'login_success.gif'; }
	if ($code eq 'error')     { $img = 'error.gif'; }
	if ($code eq 'loginfail') { $img = 'login_failed.gif'; }
	print '<table width="330" height="280" border="0" align="center" ';
	print 'cellpadding="0" cellspacing="0" background="/hotel/internet_login/'.$img.'">'."\r\n";
	print '<tr><td align="center"><br>'."\r\n";
}

sub in_array ($$)
{
	my ($search, $array_r) = @_;
	foreach my $val (@$array_r)
	{
		return 1 if ($search eq $val);
	}
	return 0;
}

sub debug
{
	my ($msg, $type) = @_;
	if (!$type)
	{
		$type = "INFO";
	}
	print LOG localtime().": $type: $msg\n" if $debug_to_logfile;
	print STDOUT $type.": " . $msg . "\n" if $debug_to_stdout;
	print "<div align='left' width='100%'>log: <span style='font-weight:normal;'>$type: $msg</span></div>\r\n" if $debug_to_web;
}

sub get_attribute
{
	my $attr = shift;
	my $sql = "SELECT value FROM config WHERE attribute = '$attr' AND active = 'Y'";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	my $ref = $sth->fetchrow_hashref();
	my $value = $ref->{'value'};
	$sth->finish();
	return $value;
}

sub vod_global_cfg
{
	my $attrsrch = shift;
	my $config_file = "/etc/vod/global.cfg";
	my $retval = '';
	if (!open(CONFFILE, "< $config_file"))
	{
		die "\n -- ERROR: VOD CONFIG ($config_file) NOT FOUND --\n\n";
	}

	# strip out commented lines and blank lines..
	my @out = grep { ! /^\s*$/ && ! /^\s*\#/ } <CONFFILE>;
	foreach (@out)
	{
		s/\n//; s/\r//;
		# search for line in the format of '<optionalwhitespace>attribute<whitespace>value<# optional comment>'
		/^\s*(\S+)\s*(\S+)\#*.*$/;
		my $attr = $1; my $val = $2;
		if ($attr eq $attrsrch && $val ne '')
		{
			$retval = $val;
			last;
		}
	}

	close(CONFFILE);
	if ($retval ne '')
	{
		return $retval;
	}
	else
	{
		die "Failed to get value for attribute: '$attrsrch' from config file.\n";
	}
}

# only call when password is found.
# returns 0 on to be activated
# returns 1 on single IP activated
# returns 2+ on multiple IPs activated for account
sub get_access_data
{
	# Check for already activated conditions (NOT NULL).
	my ($id, $type) = @_;
	my $mtype = 'visit_id'; # default for 'guest' or other type
	$mtype = 'casual_id' if ($type eq 'casual');

	my %rref=();
	my $sql = "SELECT al.*, id.*
			   FROM access_list al
			   INNER JOIN internet_deal id ON id.internet_deal_id = al.internet_deal_id
			   WHERE al." . $mtype . " = '$id'
			   AND now() >= al.entered_date_time
			   AND al.active = 'Y'
			   AND id.active = 'Y'
			   ORDER BY al.entered_date_time DESC
			   LIMIT 1";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	if (my $ref = $sth->fetchrow_hashref())
	{
		return $ref;

		# here are the hash keys in $ref..
		# they exist as a guide to what data is available.

		#
		# 'internet_deal' table
		#
		# my $internet_deal_id  = $ref->{'internet_deal_id'};
		# my $deal_type         = $ref->{'type'};
		# my $deal_description  = $ref->{'description'};
		# my $deal_price        = $ref->{'price'};
		# my $length_min        = $ref->{'length_min'};
		# my $mb_dl_limit       = $ref->{'mb_dl_limit'};
		# my $excess_per_mb     = $ref->{'excess_per_mb'};

		#
		# 'access_list' table
		#
		# my $access_list_id    = $ref->{'pk_id'}; # AS access_list_id
		# my $room_id           = $ref->{'room_id'};
		# my $visit_id          = $ref->{'visit_id'};
		# my $casual_id         = $ref->{'casual_id'};
		# my $password          = $ref->{'password'};
		# my $ip_address        = $ref->{'ip_address'};
		# my $start_date_time   = $ref->{'start_date_time'};
		# my $end_date_time     = $ref->{'end_date_time'};
		# my $entered_date_time = $ref->{'entered_date_time'};
		# my $mb_limit          = $ref->{'mb_limit'};
	}
	else
	{
		return \%rref; # not a typo.
	}
}

sub is_visit_checked_in
{
	my $sql = "SELECT v.pk_id
			   FROM visit
			   WHERE pk_id = '$visit_id'
			   AND
			   (
				 now() <= v.out_date_time  OR
				 v.out_date_time = 0       OR
				 v.out_date_time IS NULL
			   )
			   LIMIT 1";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	return $sth->rows();
}

sub is_access_activated_wireless
{
	my ($id, $type) = @_;
	my $mtype = 'visit_id'; # default for 'guest' or other type
	$mtype = 'casual_id' if ($type eq 'casual');

	# Check for already activated conditions (NOT NULL).
	my $sql = "SELECT pk_id
			   FROM access_list
			   WHERE $mtype = '$id'
			   AND ip_address      IS NOT NULL
			   AND ip_address LIKE '10.20.%'
			   AND start_date_time IS NOT NULL
			   AND end_date_time   IS NOT NULL
			   AND active = 'Y'";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	my $rc = $sth->rows();
	debug("active_wireless: $rc");
	$sth->finish();
	return $rc;
}

sub is_access_activated_wired
{
	my ($id, $type) = @_;
	my $mtype = 'visit_id'; # default for 'guest' or other type
	$mtype = 'casual_id' if ($type eq 'casual');

	# Check for already activated conditions (NOT NULL).
	my $sql = "SELECT pk_id
			   FROM access_list
			   WHERE $mtype = '$id'
			   AND ip_address      IS NOT NULL
			   AND ip_address LIKE '10.0.%'
			   AND start_date_time IS NOT NULL
			   AND end_date_time   IS NOT NULL
			   AND active = 'Y'";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	my $rc = $sth->rows();
	debug("active_wired: $rc");
	$sth->finish();
	return $rc;
}


sub is_access_activated
{
	my ($id, $type) = @_;
	my $mtype = 'visit_id'; # default for 'guest' or other type
	$mtype = 'casual_id' if ($type eq 'casual');

	# Check for already activated conditions (NOT NULL).
	my $sql = "SELECT pk_id
			   FROM access_list
			   WHERE $mtype = '$id'
			   AND ip_address      IS NOT NULL
			   AND start_date_time IS NOT NULL
			   AND end_date_time   IS NOT NULL
			   AND active = 'Y'";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	my $rc = $sth->rows();
	debug("active_total: $rc");
	$sth->finish();
	return $rc;
}

# only need to call if previously activated internet exists..
sub duplicate_ip
{
	my ($ip, $pass) = @_;
	# Check for already activated conditions (NOT NULL).
	my $sql = "SELECT pk_id
			   FROM access_list
			   WHERE ip_address = '$ip'
			   AND password = '$pass'
			   AND now() >= entered_date_time
			   AND active = 'Y'";
	#debug("duplicate_ip() SQL: '$sql'");
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	return $sth->rows();
}

# NG with casual Internet exceptions.
sub does_password_exist
{
	my $pass = shift;
	my ($id1, $id2, $esql, $sql, $rowid, $casual_support);
	my $id=0;
	my $type=0;

	if (casual_supported())
	{
		$esql = "visit_id, casual_id";
	}
	else
	{
		debug("does_password_exist() casual support disabled. Using visit_id only for password check", "WARN");
		$esql = "visit_id";
	}

	$sql = "SELECT pk_id AS al_id, " . $esql . "
			FROM access_list
			WHERE password = '$pass'
			AND active = 'Y'
			LIMIT 1";

	my $sth = $dbh->prepare($sql);
	$sth->execute();
	if (my $ref = $sth->fetchrow_hashref())
	{
		$rowid = $ref->{'al_id'};
		($id, $type) = get_client_type($ref->{'visit_id'}, $ref->{'casual_id'});
	}
	return ($id, $type);
}

sub get_client_type
{
	my ($vid, $cid) = @_;
	my $type=0;
	my $id=0;

	if (casual_supported())
	{
		if ($cid)
		{
			$type = 'casual';
			$id = $cid;
		}
		if ($vid)
		{
			if ($type)
			{
				debug("get_client_type() both visit and casual IDs set ($vid and $cid respectively) discarding 'casual_id' and using visit_id: '$vid' with 'guest' type", "WARN");
			}
			$type = 'guest';
			$id = $vid;
		}
	}
	else
	{
		if ($cid)
		{
			debug("get_client_type() whoops - found casual_id although casual_supported() is false!", "WARN");
		}
		$id = $vid;
		if (!$id)
		{
			debug("get_client_type() invalid visit_id with casual support disabled.", "ERROR");
		}
		$type = 'guest';
	}
	return ($id, $type);
}

sub update_access_list
{
	my ($rowid, $ip, $length_min) = @_;
	my $upd_sql = "UPDATE access_list
					  SET ip_address      = '$ip',
						  start_date_time = now(),
						  end_date_time   = date_add(now(),INTERVAL " . $length_min . " MINUTE)
				   WHERE pk_id = '$rowid'";
	eval { $dbh->do($upd_sql); };
	debug("access_list UPDATE DB failed (reason: " . $@ . ")", "ERROR") if $@;
	return 1;
}


sub does_field_exist
{
	my ($table, $field) = @_;
	my $sth = $dbh->prepare("LISTFIELDS " . $table);
	$sth->execute();
	my $ref = $sth->{'NAME'};
	if (grep {/^$field$/} @$ref)
	{
		return 1;
	}
	return 0;
}

sub casual_supported
{
	return 0 if (!does_field_exist('expense',    'casual_id'));
	return 0 if (!does_field_exist('iptables',   'casual_id'));
	return 0 if (!does_field_exist('access_list','casual_id'));
	return 1;
}

sub iptables_db_insert
{
	my ($id, $type, $ip, $room_id) = @_;
	my $mtype = 'visit_id'; # default for 'guest' or other type
	$mtype = 'casual_id' if ($type eq 'casual');

	debug("iptables_db_insert() Inserting DB level iptables rules for IP $ip, type: $type.");
	my $ipt_sql = "INSERT INTO iptables (room_id, $mtype, ip_address, bytes, start_date_time, end_date_time, active)
				   VALUES ('$room_id', '$id', '$ip', 0, now(), NULL, 'Y')";
	eval { $dbh->do($ipt_sql); };
	if ($@)
	{
		debug("iptables_db_insert() iptables DB INSERT: FAILED.  Reason: " . $@, "ERROR");
		debug("iptables_db_insert() iptables SQL: $ipt_sql");
	}
	else
	{
		debug("iptables_db_insert() iptables DB INSERT OK");
	}
}

sub get_syslevel_iptables
{
	my $ip = shift;
	my @iptemp = ();
	if (open(IPTVIEW, '-|', "/sbin/iptables -nvxL"))
	{
		@iptemp = <IPTVIEW>;
		close(IPTVIEW) or debug("get_syslevel_iptables() IPTVIEW (/sbin/iptables) was not closed cleanly: $!", "WARN");
	}
	else
	{
		debug("get_syslevel_iptables() IPTVIEW (/sbin/iptables) could not be executed: $!", "ERROR");
		exit 1;
	}
	my $rulecount = 0;
	my $rules = "";
	my $bytes_in = 0;
	foreach (@iptemp)
	{
		if (/$ip/)
		{
			my @ipt_row = split;
			my $byte_count = $ipt_row[1];
			my $source = $ipt_row[7];
			my $dest = $ipt_row[8];
			if ($source eq '0.0.0.0/0' && ($dest eq $ip) ) # we want to count this one..
			{
				$bytes_in += $byte_count;
			}
			if ($source ne '0.0.0.0/0' && ($source eq $ip) )
			{
				$rulecount++;
			}
			$rules .= $_."<br>\r\n";
		}
	}
	return ($rulecount, $bytes_in);
}

sub iptables_sys_insert
{
	my $ip = shift;
	my $error = 0;

	my $admin_interface = get_attribute('admin_network_interface');
	if (!$admin_interface)
	{
		$admin_interface = 'eth1';
	}

	my ($admin_net, $admin_mask) = get_real_net_mask($admin_interface);

	if (!$admin_net || !$admin_mask)
	{
		$admin_net = '169.254.0.0';
		$admin_mask = '255.255.255.254';
	}

	# when set to 0 (normal), iptables will allow fwd access to all except admin_net
	# when set to 1 (if admin_net or mask fails), iptables will allow fwd access to anything.

	if ($admin_net && $admin_mask)
	{
		debug("iptables_sys_insert() Found admin_net: $admin_net, admin_mask: $admin_mask OK");
		# untaint (1 regmatch) is required for passing it to system when suid root is used (chmod u+s)
		if ($admin_net =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/) # needs to be an IP address
		{
			$admin_net = $1; # $admin_net now untainted
		}
		else
		{
			debug("iptables_sys_insert() Bad data during untaint of admin_net: $admin_net, allowing fwd access to anything");
		}
		if ($admin_mask =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/) # needs to be an IP address
		{
			$admin_mask = $1; # $admin_mask now untainted
		}
		else
		{
			debug("iptables_sys_insert() Bad data during untaint of admin_mask: $admin_mask, allowing fwd access to anything");
		}
	}
	else
	{
		debug("iptables_sys_insert() internet interface data not available / found via ifconfig/ipcalc, allowing fwd to anything");
		# unlikely..but will stop what follows from breaking..
		$admin_net = "6.6.6.6";
		$admin_mask = "255.255.255.255";
	}

	if ($ip =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/) # needs to be an IP address
	{
		$ip = $1; # $ip now untainted
	}
	else
	{
		debug("iptables_sys_insert() Bad data during untaint of IP: $ip", "ERROR");
		die "Bad data in $ip";
	}
	# end untaints..

	my ($rulecount, $bytes_in) = get_syslevel_iptables($ip);

	if ($rulecount == 0)
	{
		debug("iptables_sys_insert() Inserting system level iptables rules for IP: $ip");
		#print "ins ipt rules<br>\r\n";

		my $rc2 = system '/sbin/iptables', '-I', 'FORWARD', '-s', $ip, '-d', '!', $admin_net.'/'.$admin_mask, '-j', 'ACCEPT'; # for access only (except internet network)
		if ($rc2 != 0)
		{
			debug("iptables_sys_insert() iptables cmd1 (add fwd src ip: $ip, real internet net) failed: $!");
			$error=1;
		}

		my $rc3 = system '/sbin/iptables', '-I', 'FORWARD', '-d', $ip, '-j', 'ACCEPT'; # for access AND usage (non http)
		if ($rc3 != 0)
		{
			debug("iptables_sys_insert() iptables cmd3 (add fwd dst ip: $ip) failed: $!");
			$error=1;
		}

		my $rc4 = system '/sbin/iptables', '-I', 'OUTPUT',  '-d', $ip, '-j', 'ACCEPT'; # for usage only (http)
		if ($rc4 != 0)
		{
			debug("iptables_sys_insert() iptables cmd4 (add output dst ip: $ip) failed: $!");
			$error=1;
		}

		return 1 if (!$error);
		return 0;
	}
	else
	{
		debug("iptables_sys_insert() $rulecount rules existed for IP: $ip, not adding anymore: bytes_in: $bytes_in", "WARN");
		return 0;
	}
}

sub get_access_type
{
	my $room_id = shift;

	my $sql = "SELECT DISTINCT access_type FROM room WHERE room_id = '$room_id'";
	my $sth = $dbh->prepare($sql);
	$sth->execute();

	my $access_type;
	if (my $ref = $sth->fetchrow_hashref())
	{
		$access_type = $ref->{'access_type'};
	}
	else
	{
		debug("get_access_type() Could not get access_type for room_id: $room_id, setting default to 'norm'", "WARN");
		$access_type = 'norm';
	}
	$sth->finish();
	return $access_type;
}

sub good_login
{
	my ($ip, $pass, $is_sec) = @_;
	pc_head('loginok');

	if ($is_sec)
	{
		#print "Multiple IP login detected.<br><br>\r\n";
		debug("good_login(): secondary login detected");
	}

	if (get_attribute('pms_name_available') == 1 && !$free_lobby)
	{
		print "<span style='font-size:17px;'>For future reference, your password is:&nbsp;</span>";
		print "<span style='font-size:22px;color:orange;'>$pass</span><br><br>\r\n";
	}
	else
	{
		print "<span style='font-size:17px;'>Access Granted</span><br><br>\r\n";
	}
	my $sql = "SELECT DISTINCT url FROM url_cache WHERE ip_address = '$ip' ORDER BY date_time DESC LIMIT 1";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	if (my $ref = $sth->fetchrow_hashref())
	{
		my $url = $ref->{'url'};
		print "Your site:&nbsp;<br>\r\n";
		print "<a class='urlcache' href=\"" . $url . "\">" . $url . "</a><br>\r\n";
	}
	else
	{
		print "<a class='urlcache' href=\"http://www.google.com/\">Search the Web</a><br><br>\r\n";
	}
	$sth->finish();
	return 1;
}

sub check_stoperrors
{
	if (! -x "/sbin/ifconfig")
	{
		print "ERROR: ifconfig (/sbin/ifconfig) program not found executable, terminating..\n";
		print LOG localtime() . ": ERROR: ifconfig (/sbin/ifconfig) program not found executable, terminating..\n";
		$dbh->disconnect();
		close(LOG);
		exit();
	}
	if (! -x "/bin/ipcalc" && -f "/etc/mandrake-release")
	{
		print "ERROR: ipcalc (/bin/ipcalc) program not found executable, terminating..\n";
		print LOG localtime() . ": ERROR: ipcalc (/bin/ipcalc) program not found executable, terminating..\n";
		$dbh->disconnect();
		close(LOG);
		exit();
	}
	if (! -x "/usr/bin/ipcalc" && -f "/etc/debian_version")
	{
		print "ERROR: ipcalc (/usr/bin/ipcalc) program not found executable, terminating..\n";
		print LOG localtime() . ": ERROR: ipcalc (/bin/ipcalc) program not found executable, terminating..\n";
		$dbh->disconnect();
		close(LOG);
		exit();
	}
}

sub internet_discount_price
{
	my ($internet_deal_id, $visit_id) = @_;
	my $count = 0;
	my $discount_rate = 0;

	my $sql = "SELECT count(*) AS count
			FROM internet_deal_session
			WHERE visit_id = '$visit_id'
			AND internet_deal_id = '$internet_deal_id'";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	if (my $ref = $sth->fetchrow_hashref())
	{
		$count = $ref->{'count'};
	}

	$sql = "SELECT *
			FROM internet_discount_rate
			WHERE internet_deal_id = '$internet_deal_id'
			AND packages_required <= '$count'
			ORDER BY packages_required DESC
			LIMIT 1";
	$sth = $dbh->prepare($sql);
	$sth->execute();

	if (my $ref = $sth->fetchrow_hashref())
	{
		$discount_rate = $ref->{'discount_rate'};
	}

	debug("internet_discount_price() $discount_rate % for deal_id: $internet_deal_id, visit_id: $visit_id");
	return $discount_rate;
}
