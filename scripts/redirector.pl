#!/usr/bin/perl -w
use DBI();
use strict;

# logfile, must be writable by squid user/group
my $lf = "/var/log/redirector/redirector.log";
my $debug=1;

my $db_name = vod_global_cfg('menu_db_name');
my $db_user = vod_global_cfg('db_user');
my $db_pass = vod_global_cfg('db_pass');
my $dbh;
db_connect();

$|=1; # must use unbuffered I/O
my $local_ip = get_attribute("web_server_ip");
my $deny_loc = get_attribute("redirector_deny_location");
my $inv_url = "http://".$local_ip."/".$deny_loc;
my %ip_cache=();
my %url_cache=();
my @wgurls_preloaded=();
#preload_walled_garden();
my $cache_time_sec=60; # expiry timer in seconds for ip and url(walled garden) cache.
my @allow_ext_list = qw/gif jpg jpeg bmp swf png js css/;

my $cnt=0;
while (<>) {
	my ($url,$host,$ident,$method) = split;
	debug("\n------------- ".localtime()." --------------------") if $debug;
	debug("URL:$url,HOST:$host,ID:$ident,METH:'$method'") if $debug;
	debug("-----------------------------------------------------") if $debug;

	if ($url =~ m|http://$local_ip/|i ) { # allow anything accessing THIS MACHINES IP..
		debug("D$cnt: url '$url' is local host, allow") if $debug;
		print $url."\n";
		next;
	}

	
	#security issue..
	#if (check_ext($url)) {
	#	debug("D$cnt: url '$url' has an allowed EXT, allow") if $debug;
	#	print $url."\n";
	#	next;
	#}

	my $ip = substr($host,0,index($host,"/"));
	if (my $iptl = ip_cached($ip)) {
		debug("D$cnt: ip '$ip' is cached, time left: $iptl") if $debug;
		print $url."\n";
		next;
	}
	
	if (my $wgtl = url_cached($url)) {
		debug("D$cnt: url '$url' cached, time left: $wgtl") if $debug;
		print $url."\n";
		next;
	}

	if (ip_authorized($ip)) {
		debug("D$cnt: ip '$ip' is authorized, caching") if $debug;
		$ip_cache{$ip}=time();
		print $url."\n";
		next;
	}

	if (check_db_walled_garden($url)) {
		debug("D$cnt: url '$url' is in WG, caching") if $debug;
		$url_cache{strip_base_url($url)}=time();
		print $url."\n";
		next;
	}		

	debug("D$cnt: url '$url', ip: '$ip' did not match any criteria, denied") if $debug;
	#$dbh->do("INSERT INTO url_cache ( ip_address, url, date_time ) VALUES ( '$ip','$url',now() )");
	#print $inv_url."\n"; # transparent redirect
	print "302:".$inv_url."\n"; # moved temp

	debug("------------------------- END ----------------------------\n") if $debug;
	$cnt++ if $debug;
}
$dbh->disconnect();

sub check_db_walled_garden {
	my $url = shift;
	my $sql = "SELECT url FROM walled_garden WHERE active = 'Y' AND url != ''";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	while (my $ref = $sth->fetchrow_hashref()) {
		#debug("A: ref->url: '".$ref->{'url'}."', passedurl: '$url'") if $debug;
		return 1 if (strip_base_url($ref->{'url'}) eq strip_base_url($url));
	}
	return 0;
}

sub check_preloaded_walled_garden {
	my $url = shift;
	foreach (@wgurls_preloaded) {
		return 1 if (strip_base_url($_) eq strip_base_url($url));
	}
	return 0;
}

sub strip_base_url {
	my $url = shift;
	$url =~ m|^(https*://[\w!:@#\.\$-]+)/*.*|;
	return $1 if ($1);
	return "";
}

sub check_ext {
	my $url = shift;
	foreach my $ext (@allow_ext_list) {
		return 1 if ($url =~ m|^https*://\S+?/.*?\.$ext$|i);
	}
	return 0;
}

sub ip_cached {
	my $ip = shift;
	if ($ip_cache{$ip}) {
		my $time_left = $cache_time_sec - (time()-$ip_cache{$ip});
		if ($time_left <= 0) { # cache expired
			$ip_cache{$ip} = 0;
			return 0;
		} else { # cached, returning time left.
			return $time_left;
		}
	} else { # not cached
		return 0;
	}
}

sub url_cached {
	my $url = strip_base_url(shift);
	if ($url) {
		if ($url_cache{$url}) {
			my $time_left = $cache_time_sec - (time()-$url_cache{$url});
			if ($time_left <= 0) { # cache expired
				$url_cache{$url} = 0;
				return 0;
			} else {
				return $time_left;
			}
		} else { # not cached
			return 0;
		}
	} else { # invalid url
		return 0;
	}
}

sub preload_walled_garden {
	my $sql = "SELECT url FROM walled_garden WHERE active = 'Y' AND url != ''";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	while (my $ref = $sth->fetchrow_hashref()) {
		push @wgurls_preloaded, $ref->{'url'};
	}
}

sub ip_authorized {
	my $ip = shift;
	my $sql = "SELECT pk_id FROM access_list WHERE ip_address = '".$ip."' AND now() >= start_date_time AND now() <= end_date_time AND active = 'Y'";
	my $sth = $dbh->prepare($sql);
	$sth->execute();
	if ($sth->rows() > 0) {
		$sth->finish();
		return 1;
	} else {
		$sth->finish();
		return 0;
	}
}

sub get_attribute {
    my $attr = shift;
    my $sql = "SELECT value FROM config WHERE attribute = '$attr' AND active = 'Y'";
    my $sth = $dbh->prepare($sql);
    $sth->execute();
    my $ref = $sth->fetchrow_hashref();
    my $value = $ref->{'value'};
    $sth->finish();
    return $value;
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

sub debug {
	my $msg = shift;
	if (-w $lf) {
		open(LOGFILE, ">> ".$lf) or die "could not open logfile for appending: $!\n";
		print LOGFILE $msg."\n";
		close(LOGFILE) or warn "logfile did not close cleanly: $!\n";
	} else {
		print STDERR "Log file '$lf' not writable / does not exist\n";
	}
	#print STDERR $msg."\n";
	#print $msg."\n";
}

sub db_connect {
        $dbh=DBI->connect("DBI:mysql:database=".$db_name.";host=localhost",$db_user,$db_pass,{'RaiseError' => 0, 'PrintError' => 0});
        if (!$dbh) {
                debug("PID $$: Could not connect to DB (".$DBI::errstr.") on first try, sleep 2secs and attempt reconnect...");
                while ( !db_err_connect() ) {}
        } else {
                debug("PID $$: Connected to DB on first try");
        }
        $dbh->{mysql_auto_reconnect} = 1;
        return;
}

sub db_err_connect {
        sleep 2;
        $dbh=DBI->connect("DBI:mysql:database=".$db_name.";host=localhost",$db_user,$db_pass,{'RaiseError' => 0, 'PrintError' => 0});
        if (!$dbh) {
                debug("PID $$: Could not connect to DB (".$DBI::errstr.") on subsequent try, sleep 2secs and attempt reconnect...");
                return 0;
        } else {
                debug("PID $$: Connected to DB on subsequent try");
        }
        return 1;
}

