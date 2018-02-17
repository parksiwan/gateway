#!/usr/bin/perl -w
use DBI();
use strict;
use POSIX; # for floor() func in seconds_to_time() v2.
my $dbh;

# set to a byte count (usually > 300000000) to simulate excess usage for testing..
# set to 0 to disable.
#my $use_fake_bytes=301222345;
my $use_fake_bytes=0;
my $logfile = "/var/log/check_limit.log";
my $debug_to_stdout=0;
my $debug_to_logfile=1;

db_connect();

$|=1; # unbuffered output setter.

my $laptop_internet_type = get_attribute("laptop_internet_type");
my $bill_freq            = get_attribute('excess_usage_bill_freq_hours');
my $kick_on_excess_use   = get_attribute('kick_on_excess_use');
my $qos_enabled          = get_attribute('qos_enabled');
my $shape_on_excess_use  = get_attribute('shape_on_excess_use');
my $do_shaping=0;
$do_shaping=1 if ($qos_enabled && $shape_on_excess_use);
my $charge_type = get_charge_type();

stoperrors_check();       # will die if some pre-reqs not found.
#rem_co_entries();         # guest only removal of 'checked out' entries
log_checked_out();
rem_unused_entries();     # remove all non-activated entries older than 1 month regardless.
check_missing_iptables(); # add system level IP tables entries when access list row(s) are valid.

#
# Get all unique IP addresses in iptables system
#
my ($ip_bc_ref,$ip_hash_ref) = get_syslevel_iptables_ips();

my $ipcnt=0;
my @unique_vids=();
my @unique_cids=();

# because multiple IPs can be deleted in one pass
# we need to keep track of which IPs NOT to check
# if they have been previsouly deleted with this var.
my @global_ips_deleted=();

# need to update all ip byte counters before the main while loop
# for excess usage charging on multiple IPs for 1 account.
update_all_ipbc($ip_bc_ref,$ip_hash_ref);

my $run_ip_count=1;
my $global_ip_count = scalar(keys(%$ip_hash_ref));

if ($global_ip_count > 0) {
	debug("CHECK MODE Init: Found $global_ip_count IP(s) to check");
	my ($access_id,$client_type);
	while (my ($ip,$ipcnt) = each %$ip_hash_ref) {

		if (grep {/^$ip$/} @global_ips_deleted) {
			debug("Ignoring IP($run_ip_count) $ip as it has been removed in a multiIP account deletion");
			next;
		}

		my (
		    $au_code,$mb_limit,$visit_id,$casual_id,$room_id,
		    $sdt_es,$edt_ts,$excess_per_mb,$byte_limit
		   ) = get_user($ip);
		
		# IF Current active users found. This is the main section.
		if ($au_code == 1) { # found 1 for this IP
			$room_id = "NA" if !$room_id;
			($access_id,$client_type) = get_client_type($visit_id,$casual_id);
			debug("Invalid client_type found: '$client_type'","ERROR") if (!$client_type);
			debug("Invalid access_id found: '$access_id'","ERROR") if (!$access_id);
			my $mtype = 'visit_id'; # default for 'guest' or other type
			$mtype = 'casual_id' if ($client_type eq 'casual');

			debug("Room: $room_id, $mtype: $access_id: Found an active IP($run_ip_count): $ip in access_list");
			
			# We only want to process unique access IDs otherwise
			# duplicate excess usage billing could occur on multiple IPs
			#
			if ($client_type eq 'guest') {
				if (grep {/^$visit_id$/} @unique_vids) {
					debug("Secondary IP($run_ip_count) $ip detected. visit_id: $visit_id has been previously processed.");
					next;
				}
				push @unique_vids, $visit_id;
			} else {
				if (grep {/^$casual_id$/} @unique_cids) {
					debug("Secondary IP($run_ip_count) $ip detected. casual_id: $casual_id has been previously processed.");
					next;
				}
				push @unique_cids, $casual_id;
			}

			#
			# BEGIN EXCESS USAGE checking on access_id (checks all IPs associated to a room)
			#
			my $mb_dl = get_mb_downloaded($access_id,$client_type);

			if ($mb_dl > $mb_limit) {

				debug("EXCESS USAGE for Room: $room_id, $mtype: $access_id. Exceeded $mb_limit MB limit, MB D/L: $mb_dl");

				if (!$do_shaping) { # shape takes precendence over kick if both are set
					if ($kick_on_excess_use || $client_type eq 'casual') {
						debug("EU DEACTIVATION for Room: $room_id, $mtype $access_id","WARN");
						remove_account($access_id,$client_type);
						next;
					}
				} else { # add shaping to link
					debug("EU SHAPING ADD for Room: $room_id, $mtype $access_id","WARN");
					shape_access_id($access_id,$client_type); # need to shape all IPs assoc to access_id.
				}

				my $excess_dl = ($mb_dl - $mb_limit);
				my $excess_cost = sprintf("%.2f",($excess_dl*$excess_per_mb));
				my $access_type;
				if ($client_type eq 'guest') {
					$access_type = get_access_type($room_id);
				} else {
					$access_type = 'norm';
				}

				#
				# (a) Can we charge excess, if so then:
				# (b) Does an existing EU expense exist, if it does then:
				# (c) How old is it and if it is old enough (bill_freq hours) then:
				# (d) Insert a new EU expense.
				#
				if (!$do_shaping && $client_type ne 'casual' && !$kick_on_excess_use) {
					if (my $date_time_ts = get_last_excess_record($access_id,$client_type)) {
						my $expense_mb;
						#debug("Room: $room_id, $mtype: $access_id: Found an existing excess usage expense row, will now check age");
	
						# Check to see if the last excess record is old enough for a new one to be put in.
						my $expense_age = seconds_to_time(time()-$date_time_ts);
						
						if ( (time()-(60*60*$bill_freq)) >= $date_time_ts) {
							debug("Room: $room_id, $mtype: $access_id: Last expense record is $expense_age old (more than $bill_freq hrs), adding new expense row");
							$expense_mb = get_accum_expense_mb($access_id,$client_type);
							my $new_expense_mb = ($excess_dl - $expense_mb);
							my $new_excess_cost = sprintf("%.2f",($new_expense_mb*$excess_per_mb));
							debug("Room: $room_id, $mtype: $access_id: Sum of all previous excess charges: $expense_mb MB, total excess (ActualDL-AllowedDL): $excess_dl MB");
	
							# Insert only if enough has been DL since last excess record.
							if ($new_excess_cost > 0) {
								debug ("EU ADDING EXTRA EXPENSE for Room: $room_id, $mtype: $access_id: $new_expense_mb MB, cost: $new_excess_cost");
	
								# EXCESS USAGE Expense INSERT
								debug("Room: $room_id, $mtype: $access_id: new excess usage expense: $new_expense_mb, cost: $new_excess_cost (it is > 0.00)");
								my $ins_sql = "INSERT INTO expense (expense, cat, cost, date_time, end_date_time, access_type, $mtype)
								               VALUES ('$new_expense_mb','Excess Internet Charge','$new_excess_cost',now(),now(),'$access_type','$access_id')";
								eval { $dbh->do($ins_sql); };
								if ($@) {
									debug("expense DB INSERT: FAILED. Reason: ".$@,"ERROR");
									debug("expense sql: $ins_sql");
								} else {
									debug("expense DB INSERT OK");
								}
	
								# EXCESS USAGE PMS Request INSERT (additional entry)
								if ($access_type eq 'norm' && $client_type eq 'guest') {
									$ins_sql = "INSERT INTO pms_request (pms_req_type,reference_code,room_no,description,charge,pms_processed,pms_req_active,retry_count)
									            VALUES ('8','$charge_type','$room_id','Excess Internet Charge','$new_excess_cost','N','Y','0')";
									eval { $dbh->do($ins_sql); };
									if ($@) {
										debug("pms_request DB INSERT: FAILED. Reason: ".$@,"ERROR");
										debug("pms_request sql: $ins_sql");
									} else {
										debug("pms_request DB INSERT OK");
									}
								}
	
							} else { # nothing downloaded since last excess record
								debug("Room: $room_id, $mtype: $access_id: Valid criteria for excess usage but the cost is zero, not inserting a zero cost expense row");
							}
	
						} else { # the last excess usage record is still current (not old enough)
							debug("Room: $room_id, $mtype: $access_id: Last expense record is $expense_age old (less than $bill_freq hrs), will not be adding a new expense yet");
						}
	
					} else { # no existing expense records at all will insert 1st one.
	
						debug("EU ADDING 1ST EXPENSE for Room: $room_id, $mtype: $access_id: New excess usage expense: $excess_dl MB, cost: $excess_cost");
	
						# EXCESS USAGE Expense INSERT (initial entry)
						my $ins_sql = "INSERT INTO expense (expense, cat, cost, date_time, end_date_time, access_type, $mtype)
						               VALUES ('$excess_dl','Excess Internet Charge','$excess_cost',now(),now(),'$access_type','$access_id')";
						eval { $dbh->do($ins_sql); };
						if ($@) {
							debug("expense DB INSERT: FAILED. Reason: ".$@,"ERROR");
							debug("expense sql: $ins_sql");
						} else {
							debug("expense DB INSERT OK");
						}
	
						# EXCESS USAGE PMS Request INSERT (initial entry)
						if ($access_type eq 'norm' && $client_type eq 'guest') {
							$ins_sql = "INSERT INTO pms_request (pms_req_type,reference_code,room_no,description,charge,pms_processed,pms_req_active,retry_count)
							            VALUES ('8','$charge_type','$room_id','Excess Internet Charge','$excess_cost','N','Y','0')";
							eval { $dbh->do($ins_sql); };
							if ($@) {
								debug("pms_request DB INSERT: FAILED. Reason: ".$@,"ERROR");
								debug("pms_request sql: $ins_sql");
							} else {
								debug("pms_request DB INSERT OK");
							}
						}
					}
				} else {
					debug("EU Not charging on excess. Client type: $client_type, DoShaping: $do_shaping, kickOnExcess: $kick_on_excess_use");
				}	
			} else { # not yet exceeded DL limit.
				debug("Room: $room_id, $mtype: $access_id: Has not yet exceeded $mb_limit MB limit, MB D/L: $mb_dl");
			}

			#
			#
			# END excess usage checking..
			#
			#



			#
			#
			# BEGIN Time checking..
			#
			#
			if ( time() >= $edt_ts ) { # time up
				debug("TIME IS UP for Room: $room_id, $mtype: $access_id, IP($run_ip_count): $ip");
				remove_account($access_id,$client_type);
			} else { # time OK
				my $time_left = seconds_to_time($edt_ts - time());
				debug("Room: $room_id, $mtype: $access_id: Time is still OK for IP($run_ip_count): $ip, time left: $time_left");
			}
			#
			#
			# END time checking..
			#
			#


		} else { # iptables IP not found in access_list, removing account.

			debug("IP($run_ip_count) $ip not found active and current in access list. Removing IP from system and DB levels");
			my $remipsql = "DELETE FROM iptables WHERE ip_address = '$ip' AND active = 'Y'";
			eval { $dbh->do($remipsql); };
			debug("iptables DB DELETE for deactivation failed (reason: ".$@."). SQL: '$remipsql'","ERROR") if $@;
			remsys_iptables($ip);

		}
		$run_ip_count++;

	} # while loop

} else {
	debug("No IP addresses found at iptables system level");
}

# remove all expired access list entries, in case they are not in the iptables system.
# this should be done after the regular checks above because they will remove expired access list
# entries under normal circumstances.
rem_exp_al_entries(); 

$dbh->disconnect();

#
#
#
#
# END main
#
#
#
#





#
#
#
#
# BEGIN subs
#
#
#

sub remove_account {
	my ($id,$type) = @_;
	my $mtype = 'visit_id'; # default for 'guest' or other type
	my $no_ip=0;
	$mtype = 'casual_id' if ($type eq 'casual');
	if (!$id) {
		debug("remove_account() Invalid or empty ID supplied, cannot run remove_account");
		return 0;
	}
	my @ips = get_ips_for_id($id,$type);
	if (!$ips[0]) {
		debug("remove_account(): warning: No IPs for account ID: $id, type: $type, just removing access_list DB entry");
		$no_ip=1;
	}
	if ($no_ip==1) {
		debug("remove_account(): No IP removal: Removing Unused $mtype account ID: $id from access_list table");
		my $dsql = "DELETE FROM access_list WHERE $mtype = '$id'";
		eval { $dbh->do($dsql); };
		if ($@) {
			debug("remove_account() SQL failed for access_list DB delete (reason: ".$@."), SQL: '$dsql'");
		} else {
			debug("remove_account() SQL OK access_list DB DELETE");
		}
	} else {
		foreach my $ip (@ips) {
			debug("remove_account() Removing IP: $ip ($mtype: $id) from iptables system and AL+IPT DB tables");
			my $dsql = "DELETE FROM access_list WHERE ip_address = '$ip'";
			eval { $dbh->do($dsql); };
			if ($@) {
				debug("remove_account() SQL failed for access_list DB delete (reason: ".$@."), SQL: '$dsql'");
			} else {
				debug("remove_account() SQL OK access_list DB DELETE");
			}
			$dsql = "DELETE FROM iptables WHERE ip_address = '$ip'";
			eval { $dbh->do($dsql); };
			if ($@) {
				debug("remove_account() SQL failed for iptables DB delete (reason: ".$@."), SQL: '$dsql'");
			} else {
				debug("remove_account() SQL OK iptables DB DELETE");
			}
			remsys_iptables($ip);
			push @global_ips_deleted, $ip;
		}
	}
	debug("remove_account() Removing DB iptables entries for $mtype: $id");
}

sub shape_access_id {
	my ($id,$type) = @_;
	my @ips = get_ips_for_id($id,$type);
	if (!$ips[0]) {
		debug("shape_access_id(): get_ips_for_id() failed (error or no IPs), cannot shape account ID: $id, type: $type");
		return 0;
	}
	foreach my $ip (@ips) {
		if ( !is_ip_shaped($ip) ) {
			debug("shape_access_id() Shaping IP: $ip ($type: $id)");
			# eth0 out shaping to 28/ceil-40 (mark 35 matches tc filter fwid 35)
			my $rc = system '/sbin/iptables', '-t', 'mangle', '-I', 'SHAPEFILTER-IN', '-d', $ip, '-j', 'MARK', '--set-mark', '35';
			if ($rc != 0) {
				debug("shape_access_id() iptables shape (ins sf_mng dst ip: $ip) failed: $! (rc $rc)","WARN");
			} else {
				debug("shape_access_id() iptables shape (ins sf_mng dst ip: $ip) OK");
			}
		} else {
			debug("shape_access_id() IP: $ip already shaped, not shaping this time");
		}
	}
}

sub get_ips_for_id {
	my ($id,$type) = @_;
	my $mtype = 'visit_id'; # default for 'guest' or other type
	$mtype = 'casual_id' if ($type eq 'casual');
	my @ips=();
	if (!$id) {
		debug("get_ips_for_id() Invalid or empty ID supplied, cannot run get_ips_for_id()");
		return 0;
	}
	my $sql = "SELECT ip_address AS ip
	           FROM access_list
	           WHERE $mtype = '$id'
	           AND ip_address IS NOT NULL
	           AND ip_address != ''
	           ORDER BY entered_date_time DESC";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	debug("get_ips_for_id() Found ".$sth->rows()." IP(s) for $mtype: $id in access_list DB");
	while (my $ref = $sth->fetchrow_hashref()) {
		my $ip = $ref->{'ip'};
		push @ips, $ip;
	}
	return @ips;
}

sub is_ip_shaped {
        my $ip = shift;
        my $ipt = `/sbin/iptables -nvL SHAPEFILTER-IN -t mangle`;
        my @output = split(/\n/,$ipt);
        foreach (@output) {
                return 1 if (/$ip\s+MARK\sset\s0x23/);
                # iptables 1.4.1.1+
                return 1 if (/$ip\s+MARK\sxset\s0x23/);
        }
        return 0;
}

sub remsys_iptables {
	my $ip = shift;
	if (!$ip) {
		debug("remsys_iptables() Invalid or empty IP supplied, cannot run remsys_iptables");
		return 0;
	}

	my $admin_interface = get_attribute('admin_network_interface');
	if (!$admin_interface) {
		$admin_interface = 'eth1';
	}

	my ($admin_net,$admin_mask) = get_real_net_mask($admin_interface);

	if (!$admin_net || !$admin_mask)
	{
		$admin_net = '169.254.0.0';
		$admin_mask = '255.255.255.254';
	}

	my $rc1 = system '/sbin/iptables', '-D', 'FORWARD', '-s', $ip, '-d', '!', $admin_net.'/'.$admin_mask, '-j', 'ACCEPT'; # for access only (except admin_int network)
	if ($rc1 != 0) {
		debug("remsys_iptables() iptables cmd1 (del fwd src ip: $ip, real admin_int) failed: $!","ERROR");
	} else {
		debug("remsys_iptables() iptables cmd1 (del fwd src ip: $ip, real admin_int) OK");
	}
	my $rc3 = system '/sbin/iptables', '-D', 'FORWARD', '-d', $ip, '-j', 'ACCEPT'; # for access AND usage (non http)
	if ($rc3 != 0) {
		debug("remsys_iptables() iptables cmd3 (del fwd dst ip: $ip) failed: $!","ERROR");
	} else {
		debug("remsys_iptables() iptables cmd3 (del fwd dst ip: $ip) OK");
	}
	my $rc4 = system '/sbin/iptables', '-D', 'OUTPUT',  '-d', $ip, '-j', 'ACCEPT'; # for usage only (http)
	if ($rc4 != 0) {
		debug("remsys_iptables() iptables cmd4 (del output dst ip: $ip) failed: $!","ERROR");
	} else {
		debug("remsys_iptables() iptables cmd4 (del output dst ip: $ip) OK");
	}
	if ($do_shaping) { # only do if qos/shaping config is enabled.
		if ( is_ip_shaped($ip) ) {
			debug("remsys_iptables() IP $ip is in the iptables shape list, will now remove.");
			my $rc5 = system '/sbin/iptables', '-t', 'mangle', '-D', 'SHAPEFILTER-IN', '-d', $ip, '-j', 'MARK', '--set-mark', '35';
			if ($rc5 != 0) {
				debug("remsys_iptables() iptables cmd5 (del sf_mng dst ip: $ip) failed: $!","ERROR");
			} else {
				debug("remsys_iptables() iptables cmd5 (del sf_mng dst ip: $ip) OK");
			}
		}
	}
	return 1;
}

sub get_real_net_mask {
	my $if = shift;
	my $ifc = `/sbin/ifconfig $if`;
	my ($ip,$bcast,$mask);
	if ($ifc =~ /inet\saddr:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*Bcast:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*Mask:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
		$ip    = $1;
		$mask  = $3;
		if (-f "/etc/mandrake-release") {
			my $net = `/bin/ipcalc -n $ip $mask`;
			if ($net =~ /^NETWORK=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
				$net = $1;
				return ($net,$mask);
			} else {
				return (0,0);
			}
		} else {
			my $net = `/usr/bin/ipcalc -n -b $ip $mask`;
			if ($net =~ /Network:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/.*/mi) {
				$net = $1;
				return ($net,$mask);
			} else {
				return (0,0);
			}
		}
	} else {
		return (0,0);
	}
}


sub debug {
	my ($msg,$type) = @_;
	if (!$type) { $type = "INFO"; }
	open(LOG, ">> $logfile") or die "LOG file: $logfile could not be opened for writing: $!\n";
	print LOG localtime().": $type: $msg\n" if $debug_to_logfile;
	close(LOG) or warn "LOG file: $logfile could not be closed cleanly: $!\n";
	print STDOUT $type.": ".$msg."\n" if $debug_to_stdout;
}

sub get_attribute {
	my $attr = shift;
	my $value = "";
	my $sql = "SELECT value FROM config WHERE attribute = '$attr' AND active = 'Y'";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	if (my $ref = $sth->fetchrow_hashref()) {
		$value = $ref->{'value'};
	}
	$sth->finish();
	return $value;
}

sub seconds_to_time {
	# STTv2
	my $seconds=shift;
	my $minus="";
	return "0m:0s" if($seconds==0);
	if($seconds < 0){$minus="-";$seconds=abs($seconds);}
	return $minus."0m:".$seconds."s" if($seconds<60);
	my $mins=floor($seconds/60);
	my $srem=$seconds%60;
	return $minus.$mins."m:".$srem."s" if($mins<60);
	my $hrs=floor($mins/60);
	my $mrem=$mins%60;
	return $minus.$hrs."h:".$mrem."m:".$srem."s";
}

sub vod_global_cfg {
    my $attrsrch = shift;
    my $config_file = "/etc/vod/global.cfg";
    my $retval = '';
    if (!open(CONFFILE, "< $config_file")) {
        die "\n -- ERROR: VOD CONFIG ($config_file) NOT FOUND --\n\n";
    }

    # strip out commented lines and blank lines..
    my @out = grep { ! /^\s*$/ && ! /^\s*\#/ } <CONFFILE>;
    foreach (@out) {
        s/\n//; s/\r//;
        # search for line in the format of '<optionalwhitespace>attribute<whitespace>value<# optional comment>'
        /^\s*(\S+)\s*(\S+)\#*.*$/;
        my $attr = $1; my $val = $2;
        if ($attr eq $attrsrch && $val ne '') {
            $retval = $val;
            last;
        }
    }

    close(CONFFILE);
    if ($retval ne '') {
        return $retval;
    } else {
        die "Failed to get value for attribute: '$attrsrch' from config file.\n";
    }
}

sub get_syslevel_iptables_ips {
	my %ip_bc;
	my %ip_hash;
	open(IPTVIEW, '-|', "/sbin/iptables -nvxL");
	my @iptemp = <IPTVIEW>;
	close(IPTVIEW);
	#
	# be careful with this when adding new or different rows to iptables
	# for increased func. or security.
	#
	# looks for 2 DST IPs with SRC==0.0.0.0/0 for outbound (to client from us,
	# meaning client downloads) byte count.
	foreach (@iptemp) {
		if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {
			my @ipt_row = split;
			my $byte_count = $ipt_row[1];
			my $source = $ipt_row[7];
			my $dest = $ipt_row[8];
			if ($source eq '0.0.0.0/0' && $dest ne '0.0.0.0/0' && $dest ne '255.255.255.255') {
				$ip_bc{$dest} += $byte_count;
				$ip_hash{$dest} += 1;
			}
		}
	}
	return (\%ip_bc,\%ip_hash);
}

sub get_access_type {
	my $room_id = shift;

	my $sql = "SELECT DISTINCT access_type FROM room WHERE room_id = '$room_id'";
	my $sth = $dbh->prepare($sql);
	$sth->execute();

	my $access_type;
	if (my $ref = $sth->fetchrow_hashref()) {
		$access_type = $ref->{'access_type'};
	} else {
		debug("get_access_type() Could not get access_type for room_id: $room_id, setting default to 'norm'","WARN");
		$access_type = 'norm';
	}
	$sth->finish();
	return $access_type;
}

sub get_accum_expense_mb {
	my ($id,$type) = @_;
	my $mtype = 'visit_id'; # default for 'guest' or other type
	$mtype = 'casual_id' if ($type eq 'casual');

	my $sql = "SELECT SUM(expense) AS sum_expense
	           FROM expense
	           WHERE $mtype = '$id'
	           AND cat = 'Excess Internet Charge'
	           LIMIT 1";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	if (my $ref = $sth->fetchrow_hashref()) {
		return $ref->{'sum_expense'};
	} else {
		debug("get_accum_expense_mb() No previous Excess Internet Charge expenses found.","WARN");
		return 0;
	}
}

sub get_mb_downloaded {
	my ($id,$type) = @_;
	my $mtype = 'visit_id'; # default for 'guest' or other type
	$mtype = 'casual_id' if ($type eq 'casual');

	my $sql = "SELECT $mtype, SUM(ip.bytes) AS sum_bytes
	            FROM iptables ip
	            WHERE $mtype = '$id'
	            AND active = 'Y'
	            GROUP BY $mtype";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	if (my $ref = $sth->fetchrow_hashref()) {
		my $sum_bytes = $ref->{'sum_bytes'};
		$sth->finish();
		my $mb_dl = sprintf("%.0f",($sum_bytes/(1000*1000)));
		return $mb_dl;
	} else {
		debug("get_mb_downloaded() Could not get bytes downloaded info from iptables DB table (access_id: '$id', mtype: '$mtype').","ERROR");
		$sth->finish();
		return 0;
	}
}

sub get_last_excess_record {
	my ($id,$type) = @_;
	my $mtype = 'visit_id'; # default for 'guest' or other type
	$mtype = 'casual_id' if ($type eq 'casual');

	my $sql = "SELECT date_time,
	                  unix_timestamp(date_time) AS dt_ts
	        FROM expense
	        WHERE $mtype = '$id'
	        AND cat = 'Excess Internet Charge'
	        ORDER BY date_time DESC
	        LIMIT 1";
	#debug("GLER SQL: '$sql'");
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	if (my $ref = $sth->fetchrow_hashref()) {
		$sth->finish();
		return $ref->{'dt_ts'};
	} else {
		$sth->finish();
		return 0;
	}
}

sub update_iptables_db_bytes {
		my ($ip,$bytes) = @_;
		my $ipupsql = "UPDATE iptables SET bytes = '$bytes' WHERE ip_address = '$ip' AND active = 'Y'";
		eval { $dbh->do($ipupsql); };
		if ($@) {
			debug("update_iptables_db_bytes() iptables UPDATE for byte counter failed (reason: ".$@."). SQL: '$ipupsql'","ERROR");
			return 0;
		} else {
			return 1;
		}
}

sub get_charge_type {
	my $c = get_attribute('charge_type');
	if (!$c || $c == 'none') { $c = "02"; }
	return $c;
}

sub get_client_type {
	my ($vid,$cid) = @_;
	my $type=0;
	my $id=0;

	if (casual_supported()) {
		if ($cid) {
			$type = 'casual';
			$id = $cid;
		}
		if ($vid) {
			if ($type) { debug("get_client_type() both visit and casual IDs set ($vid and $cid respectively) discarding 'casual_id' and using visit_id: '$vid' with 'guest' type","WARN"); }
			$type = 'guest';
			$id = $vid;
		}
	} else {
		debug("get_client_type() Casual user support not detected, client_type will be 'guest'");
		if ($cid) {
			debug("get_client_type() Found casual_id although casual_supported() is false!","ERROR");
		}
		$id = $vid;
		if (!$id) {
			debug("get_client_type() invalid visit_id with casual user support disabled.","ERROR");
		}
		$type = 'guest';
	}
	return ($id,$type);
}

sub casual_supported {
	return 0 if (!does_field_exist('expense',    'casual_id'));
	return 0 if (!does_field_exist('iptables',   'casual_id'));
	return 0 if (!does_field_exist('access_list','casual_id'));
	return 1;
}

sub rem_co_entries {
	# check for "checked out" access list entries
	my $sql = "SELECT al.*
	           FROM access_list al
	           INNER JOIN visit v ON v.pk_id = al.visit_id
	           WHERE v.out_date_time != ''
	           AND v.out_date_time IS NOT NULL
	           AND v.out_date_time != '0000-00-00 00:00:00'";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	my $expired_rows = $sth->rows();
	if ($expired_rows) {
		debug("rem_co_entries() $expired_rows Checked out Internet access_list rows to deactivate found.");
		while (my $ref = $sth->fetchrow_hashref()) {
			my $expired_id = $ref->{'visit_id'};
			remove_account($expired_id,"guest");
		}
	} else {
		#debug("rem_co_entries() No Checked out Internet records found.");
	}
	$sth->finish();
}

sub log_checked_out {
	# check for "checked out" access list entries
	
	my $sql = "SELECT al.*
		FROM access_list al
		INNER JOIN visit v ON v.pk_id = al.visit_id
		WHERE v.out_date_time != ''
		AND v.out_date_time IS NOT NULL
		AND v.out_date_time != '0000-00-00 00:00:00'";
	my $sth = $dbh->prepare($sql);
	eval {
		$sth->execute();
	};
	if ($@) {
		debug("log_checked_out SQL error: '".$@."'");
		if ( !$dbh->ping() ) {
			debug("DB has gone away, reconnecting..","WARN");
			eval { $dbh->disconnect(); };
			db_connect();
		}
	}
	my $expired_rows = $sth->rows();
	if ($expired_rows) {
		debug("log_checked_out: $expired_rows checked out internet accounts (notification only)");
		while (my $ref = $sth->fetchrow_hashref()) {
			my $expired_id   = $ref->{'visit_id'};
			my $expired_room = $ref->{'room_id'};
			my $expired_ip   = $ref->{'ip_address'};
			if ( !defined($expired_ip) ) {
				$expired_ip = 'not_activated';
			}
			debug("log_checked_out: visit_id: $expired_id, room: $expired_room, ip: $expired_ip is checked out");
		}
	} else {
		debug("log_checked_out: no checked out internet records found");
	}
	$sth->finish();
}

#
# This sub (rem_exp_al_entries) is to remove expired access list entries that have no corresponding IP in iptables.
#
# This can happen because only "active" access list IPs are added if they are lost from the
# iptables system.
#
# So if the machine is off at the point when an access list row should expire, the expired
# entry will not be added to iptables system and that access list row will not be cleaned up
# by the normal process
#
# This sub is here to fix that and should be run after the "normal" processing.
#
sub rem_exp_al_entries {
	# check for "checked out" access list entries
	my $sql = "SELECT *
	           FROM access_list
	           WHERE (end_date_time != '' AND end_date_time IS NOT NULL AND end_date_time != 0)
	           AND (ip_address != '' AND ip_address IS NOT NULL)
	           AND now() >= end_date_time";

	my $sth = $dbh->prepare($sql);
	$sth->execute();
	my $expired_rows = $sth->rows();
	if ($expired_rows) {
		debug("rem_exp_al_entries() $expired_rows Expired access_list row(s) to remove found.");
		while (my $ref = $sth->fetchrow_hashref()) {

			my $access_list_id = $ref->{'pk_id'};
			my $ip             = $ref->{'ip_address'};
			my $room_id        = $ref->{'room_id'};
			my $visit_id       = $ref->{'visit_id'};
			my $casual_id      = $ref->{'casual_id'};
			
			my $id = $casual_id;
			my $mtype = 'casual_id';
			if ($visit_id) {
				$id = $visit_id;
				$mtype = 'visit_id';
			}

			debug("rem_exp_al_entries() Removing IP: $ip ($mtype: $id) from access_list and iptables DB tables");
			my $dsql = "DELETE FROM access_list WHERE pk_id = '$access_list_id'";
			eval { $dbh->do($dsql); };
			if ($@) {
				debug("rem_exp_al_entries() SQL failed for access_list DB delete (reason: ".$@."), SQL: '$dsql'");
			} else {
				debug("rem_exp_al_entries() SQL OK access_list DB DELETE");
			}
			$dsql = "DELETE FROM iptables WHERE ip_address = '$ip'";
			eval { $dbh->do($dsql); };
			if ($@) {
				debug("rem_exp_al_entries() SQL failed for iptables DB delete (reason: ".$@."), SQL: '$dsql'");
			} else {
				debug("rem_exp_al_entries() SQL OK iptables DB DELETE");
			}
		}
	} else {
		#debug("rem_exp_al_entries() No Expired access_list rows found.");
	}
	$sth->finish();
}


sub rem_unused_entries {
	# check for old unused access list entries
	my $sql = "SELECT *
	           FROM access_list
	           WHERE start_date_time IS NULL
	           AND date_sub(now(), INTERVAL 1 MONTH) > entered_date_time";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	my $expired_rows = $sth->rows();
	if ($expired_rows) {
		debug("rem_unused_entries() $expired_rows unused expired Internet access_list rows to deactivate found.");
		while (my $ref = $sth->fetchrow_hashref()) {
			my $vid = $ref->{'visit_id'};
			my $cid = $ref->{'casual_id'};
			my ($id,$type) = get_client_type($vid,$cid);
			remove_account($id,$type);
		}
	} else {
		#debug("rem_unused_entries() No unused expired Internet records found.");
	}
	$sth->finish();
}

sub get_user { # by ip address, active=Y, activated and may be expired
	my $ip = shift;	
	my $sql = "SELECT
		          al.*,
		          unix_timestamp(al.start_date_time) AS sdt_ts,
		          unix_timestamp(al.end_date_time) AS edt_ts,
		          id.excess_per_mb
		   FROM access_list al
		   INNER JOIN internet_deal id ON id.internet_deal_id = al.internet_deal_id
		   WHERE al.ip_address = '$ip'
		   AND al.active = 'Y'";
	my $sth = $dbh->prepare($sql);
	$sth->execute();

	if (my $ref = $sth->fetchrow_hashref()) {
		my $mb_limit      = $ref->{'mb_limit'};
		my $visit_id      = $ref->{'visit_id'};
		my $casual_id     = $ref->{'casual_id'};
		my $room_id       = $ref->{'room_id'};
		my $sdt_ts        = $ref->{'sdt_ts'};
		my $edt_ts        = $ref->{'edt_ts'};
		my $excess_per_mb = $ref->{'excess_per_mb'};
		my $byte_limit    = ($mb_limit * 1000000);
		$sth->finish();
		return (1,$mb_limit,$visit_id,$casual_id,$room_id,$sdt_ts,$edt_ts,$excess_per_mb,$byte_limit);
	} else {
		$sth->finish();
		return (0);
	}
}

sub get_all_active_users {
	my $ip = shift;	
	my $sql = "SELECT * FROM access_list
	           WHERE active = 'Y'
	           AND now() >= start_date_time
	           AND now() <= end_date_time
	           AND ip_address IS NOT NULL
	           AND ip_address != ''";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	my $cnt=0;
	my @users=();
	while (my $ref = $sth->fetchrow_hashref()) {
		my $ip  = $ref->{'ip_address'};
		my $vid = $ref->{'visit_id'};
		my $cid = $ref->{'casual_id'};
		my $rid = $ref->{'room_id'};
		$users[$cnt] = [ ($ip,$vid,$cid,$rid) ];
		$cnt++;
	}
	debug("get_all_active_users() Found $cnt activated, current users");
	return @users;
}

sub get_iptables_db {
	my $ip = shift;
	my $sql = "SELECT count(*) AS cnt FROM iptables WHERE ip_address = '$ip'";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	my $rows=0;
	if (my $ref = $sth->fetchrow_hashref() ) {
		$rows = $ref->{'cnt'};
		debug("get_iptables_db() Found $rows iptables DB row(s) for IP: $ip");
	} else {
		debug("get_iptables_db() Failed to get iptables DB counter for IP: $ip","ERROR");
	}
	$sth->finish();
	return $rows;
}

sub stoperrors_check {
	if ($laptop_internet_type ne '' && $laptop_internet_type ne 'internal_squid') {
		debug("Invalid laptop internet type ($laptop_internet_type) for check_limit.pl, exit 1","ERROR");
		exit 1;
	}
	if (! -x "/sbin/ifconfig") {
		debug("ifconfig (/sbin/ifconfig) program not found executable, exit 1","ERROR");
		exit 1;
	}
	if (! -x "/sbin/iptables") {
		debug("iptables (/sbin/iptables) program not found executable, exit 1","ERROR");
		exit 1;
	}
	if (! -x "/bin/ipcalc" && -f "/etc/mandrake-release") {
		debug("ipcalc (/bin/ipcalc) program not found executable, exit 1","ERROR");
		exit 1;
	}
	if (! -x "/usr/bin/ipcalc" && -f "/etc/debian_version") {
		debug("ipcalc (/bin/ipcalc) program not found executable, exit 1","ERROR");
		exit 1;
	}
}

sub does_field_exist {
	my ($table,$field) = @_;
	my $sth = $dbh->prepare("LISTFIELDS ".$table);
	$sth->execute();
	my $ref = $sth->{'NAME'};
	if (grep {/^$field$/} @$ref) {
		return 1;
	}
	return 0;
}

sub update_all_ipbc {
	my ($ip_bc_ref,$ip_hash_ref) = @_;
	my $gc=1;
	my $error=0;
	my $cnt = scalar(keys(%$ip_hash_ref));
	if ($cnt) {
		while (my ($ip,$ipcnt) = each %$ip_hash_ref) {
			# fake bytes testing override..
			$ip_bc_ref->{$ip} = $use_fake_bytes if $use_fake_bytes;
			#
			debug("update_all_ipbc() Processing iptables IP ($gc/$cnt): $ip, bytes in ".$ip_bc_ref->{$ip});
			if ($ipcnt != 2) { # error, it should be 2
				debug("update_all_ipbc() $ipcnt rules found for IP: $ip, should be 2, deleting 1 set","WARN");
				while ($ipcnt > 2) {
					remsys_iptables($ip);
					$ipcnt--;
				}
			}
			my $rc = update_iptables_db_bytes($ip,$ip_bc_ref->{$ip});
			$gc++;
			$error=1 if !$rc;
		}
	} else {
		return 0; # no error
	}
	return 1 if $error;
}

sub addsys_iptables {
	my $ip = shift;
	my $error=0;

	my $admin_interface = get_attribute('admin_network_interface');
	if (!$admin_interface) {
		$admin_interface = 'eth1';
	}

	my ($admin_net,$admin_mask) = get_real_net_mask($admin_interface);
	if (!$admin_net || !$admin_mask) {
		($admin_net,$admin_mask) = get_real_net_mask('eth1');
	}

	# when set to 0 (normal), iptables will allow fwd access to all except admin_net
	# when set to 1 (if admin_net or mask fails), iptables will allow fwd access to anything.
	my $allow_ip_fwd_to_all=0;

	if ($admin_net && $admin_mask) {
		debug("iptables_sys_insert() Found admin_net: $admin_net, admin_mask: $admin_mask OK");
		# untaint (1 regmatch) is required for passing it to system when suid root is used (chmod u+s)
		if ($admin_net =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/) { # needs to be an IP address
			$admin_net = $1; # $admin_net now untainted
		} else {
			$allow_ip_fwd_to_all=1;
			debug("iptables_sys_insert() Bad data during untaint of admin_net: $admin_net, allowing fwd access to anything");
		}
		if ($admin_mask =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/) { # needs to be an IP address
			$admin_mask = $1; # $admin_mask now untainted
		} else {
			$allow_ip_fwd_to_all=1;
			debug("iptables_sys_insert() Bad data during untaint of admin_mask: $admin_mask, allowing fwd access to anything");
		}
	} else {
		debug("iptables_sys_insert() admin_int data not available / found via ifconfig/ipcalc, allowing fwd to anything");
		$allow_ip_fwd_to_all=1;
	}

	if ($ip =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/) { # needs to be an IP address
		$ip = $1; # $ip now untainted
	} else {
		debug("iptables_sys_insert() Bad data during untaint of IP: $ip","ERROR");
		die "Bad data in $ip";
	}
	# end untaints..

	my ($rulecount,$bytes_in) = get_syslevel_iptables($ip);

	if ($rulecount == 0) {
		debug("iptables_sys_insert() Inserting system level iptables rules for IP: $ip");
		#print "ins ipt rules<br>\r\n";
		if ($allow_ip_fwd_to_all) {
			my $rc1 = system '/sbin/iptables', '-I', 'FORWARD', '-s', $ip, '-j', 'ACCEPT'; # for access only (to anything - admin_int info not available, obsolete and insecure last resort).
			if ($rc1 != 0) {
				debug("iptables_sys_insert() iptables cmd2 (add fwd src ip: $ip, any fwd) failed: $!");
				$error=1;
			} else {
				debug("iptables_sys_insert() iptables cmd2 (add fwd src ip: $ip, any fwd) OK");
			}

		} else {
			my $rc2 = system '/sbin/iptables', '-I', 'FORWARD', '-s', $ip, '-d', '!', $admin_net.'/'.$admin_mask, '-j', 'ACCEPT'; # for access only (except admin_int network)
			if ($rc2 != 0) {
				debug("iptables_sys_insert() iptables cmd1 (add fwd src ip: $ip, real admin_int) failed: $!");
				$error=1;
			} else {
				debug("iptables_sys_insert() iptables cmd1 (add fwd src ip: $ip, real admin_int) OK");
			}
		}

		my $rc3 = system '/sbin/iptables', '-I', 'FORWARD', '-d', $ip, '-j', 'ACCEPT'; # for access AND usage (non http)
		if ($rc3 != 0) {
			debug("iptables_sys_insert() iptables cmd3 (add fwd dst ip: $ip) failed: $!");
			$error=1;
		} else {
			debug("iptables_sys_insert() iptables cmd3 (add fwd dst ip: $ip) OK");
		}

		my $rc4 = system '/sbin/iptables', '-I', 'OUTPUT',  '-d', $ip, '-j', 'ACCEPT'; # for usage only (http)
		if ($rc4 != 0) {
			debug("iptables_sys_insert() iptables cmd4 (add output dst ip: $ip) failed: $!");
			$error=1;
		} else {
			debug("iptables_sys_insert() iptables cmd4 (add output dst ip: $ip) OK");
		}

		return 1 if (!$error);
		return 0;

	} else {
		debug("iptables_sys_insert() $rulecount rules existed for IP: $ip, not adding anymore: bytes_in: $bytes_in","WARN");
		return 0;
	}
}

sub check_missing_iptables {
	my $rc=0;
	my @users = get_all_active_users();
	my $cnt=0;
	my $syscntok=0;
	my $syscntfail=0;
	my $dbcnt=0;
	foreach my $row (@users) {
		my ($ip,$vid,$cid,$rid) = @$row;
		my ($rules,$bytes) = get_syslevel_iptables($ip);
		if (!$rules) {
			debug("check_missing_iptables() Access List IP: $ip found without system iptables rules, adding","WARN");
			if ( addsys_iptables($ip) ) {
				$syscntok++;
				debug("check_missing_iptables() IP: $ip added to system level OK");
				if ( !get_iptables_db($ip) ) {
					debug("check_missing_iptables() IP: $ip not found in iptables DB either, adding","WARN");
					my ($id,$type) = get_client_type($vid,$cid);
					iptables_db_insert($id,$type,$ip,$rid);
					$dbcnt++;
				} else {
					debug("check_missing_iptables() IP: $ip found in iptables DB OK");
				}
			} else {
				debug("check_missing_iptables() IP: $ip add to system level failed","ERROR");
				$rc=1;
				$syscntfail++;
			}
		} else {
			debug("check_missing_iptables() Access List IP: $ip found in system OK");
		}
		$cnt++;
	}
	debug("check_missing_iptables() Stats: Total:$cnt, SysAddOK:$syscntok, SysAddFail:$syscntfail, DBAdd:$dbcnt");
	return $rc;
}

sub get_syslevel_iptables {
	my $ip = shift;
	my @iptemp=();
	if (open(IPTVIEW, '-|', "/sbin/iptables -nvxL")) {
		@iptemp = <IPTVIEW>;
		close(IPTVIEW) or debug("get_syslevel_iptables() IPTVIEW (/sbin/iptables) was not closed cleanly: $!","WARN");
	} else {
		debug("get_syslevel_iptables() IPTVIEW (/sbin/iptables) could not be executed: $!","ERROR");
		exit 1;
	}
	my $rulecount=0;
	my $bytes_in=0;
	foreach (@iptemp) {
		if (/$ip/) {
			my @ipt_row = split;
			my $byte_count = $ipt_row[1];
			my $source = $ipt_row[7];
			my $dest = $ipt_row[8];
			if ($source eq '0.0.0.0/0' && $dest eq $ip) { # we want to count this one..
				$bytes_in += $byte_count;
			}

			# we don't want $ip 10.0.7.2 (for example) to match $source or $dest 10.0.7.234
			# this extra check ensures we only match 10.0.7.2 on source and dest
			if ($dest eq $ip || $source eq $ip) {
				$rulecount++;
			}
		}
	}
	return ($rulecount,$bytes_in);
}

sub iptables_db_insert {
	my ($id,$type,$ip,$room_id) = @_;
	my $mtype = 'visit_id'; # default for 'guest' or other type
	$mtype = 'casual_id' if ($type eq 'casual');

	debug("iptables_db_insert() Inserting DB level iptables rules for IP $ip, type: $type.");
	my $ipt_sql = "INSERT INTO iptables (room_id, $mtype, ip_address, bytes, start_date_time, end_date_time, active)
	               VALUES ('$room_id', '$id', '$ip', 0, now(), NULL, 'Y')";
	eval { $dbh->do($ipt_sql); };
	if ($@) {
		debug("iptables_db_insert() iptables DB INSERT: FAILED.  Reason: ".$@,"ERROR");
		debug("iptables_db_insert() iptables SQL: $ipt_sql");
	} else {
		debug("iptables_db_insert() iptables DB INSERT OK");
	}
}

sub db_connect {
	my $db_name = vod_global_cfg('menu_db_name');
	my $db_user = vod_global_cfg('db_user');
	my $db_pass = vod_global_cfg('db_pass');
	$dbh=DBI->connect("DBI:mysql:database=".$db_name.";host=localhost",$db_user,$db_pass,{'RaiseError' => 1});
}


