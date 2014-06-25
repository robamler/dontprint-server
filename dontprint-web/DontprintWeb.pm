package DontprintWeb;

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(err checkLoginAndGetUserId);

use Digest::SHA qw(hmac_sha256);
#use MIME::Base64;
use JSON;
require LWP::Simple;


sub err {
	print "{\"success\":false,\"errno\":$_[0],\"message\":\"$_[1]\"}";
	if (defined $dbh) {
		$dbh->disconnect();
	}
	exit;
}


#copied from MIME::Base64::URLSafe (which isn't available on namecheap servers)
#sub urlsafe_b64decode {
#	my $data = $_[0];
#	# +/ should not be handled, so convert them to invalid chars
#	# also, remove spaces (\t..\r and SP) so as to calc padding len
#	$data =~ tr|\-_\t-\x0d |+/|d;
#	my $mod4 = length($data) % 4;
#	if ($mod4) {
#		$data .= substr('====', $mod4);
#	}
#	return decode_base64($data);
#}


#copied from MIME::Base64::URLSafe (which isn't available on namecheap servers)
#sub urlsafe_b64encode {
#	my $data = encode_base64($_[0], '');
#	$data =~ tr|+/=|\-_|d;
#	return $data;
#}


# sub checkSreqAndExtractFbId {
# 	my $signedRequest = $_[0];
# 	my ($part1, $part2) = split('\.', $signedRequest);
# 	my $hashed = urlsafe_b64encode(hmac_sha256($part2, '7274fba46f2ed075104890cae43bb3e9'));
# 	if ($hashed eq $part1) {
# 		my $fbid = decode_json(urlsafe_b64decode($part2))->{'user_id'};
# 		if (defined $fbid) {
# 			return "$fbid fb";
# 		} else {
# 			return undef;
# 		}
# 	} else {
# 		return undef;
# 	}
# }


sub checkFbAccessToken {
	my $accessToken = $_[0];
	if (not $accessToken =~ /^[A-Za-z0-9]+$/) {
		err(5, 'Illegal characters in access token');
	}
	
	my $sth = $dbh->prepare('SELECT userId, expiresAt, FROM accesstokens WHERE accessToken=?');
	$sth->execute($accessToken);
	my $ret = $sth->fetchrow_arrayref();
	
	if (defined $ret and $ret->[1] > time) {
		return $ret->[0];
	}
	
	my $resp = LWP::Simple::get("https://graph.facebook.com/debug_token?access_token=434963003292220|__APP_SECRET__&input_token=$accessToken");
	
	my $json = decode_json($resp)->{'data'};
	if (not $json->{'is_valid'}  or  $json->{'app_id'} != 434963003292220) {
		err(6, 'Access token invalid.');
	}
	
	my $id = "$json->{'user_id'} fb";
	
	$dbh->do('INSERT INTO accesstokens (accessToken, userId, expiresAt) VALUES (?,?,?) ON DUPLICATE KEY UPDATE userId=VALUES(userId), expiresAt=VALUES(expiresAt)', undef, $accessToken, $id, $json->{'expires_at'});
	
	return $id;
}


sub checkPassword {
	my $id = "$_[0] username";
	my $passw = $_[1];
	
	my $sth = $dbh->prepare('SELECT salt, saltedpassword, failedtries, failureexpiration, CURRENT_TIMESTAMP FROM dontprintwebaccounts WHERE id=?');
	$sth->execute($id);
	my $ret = $sth->fetchrow_arrayref();
	
	if (not defined $ret) {
		err(3, 'Username or password incorrect.');
	}
	
	if ($ret->[2] >= 3 and $ret->[3] gt $ret->[4]) {
		err(4, 'Too many failed login attempts within the last hour. Please wait before you try again.');
	}
	
	if ($ret->[1] ne hmac_sha256($passw, $ret->[0])) {
		if ($ret->[3] gt $ret->[4]) {
			$dbh->do('UPDATE dontprintwebaccounts SET failedtries=failedtries+1, failureexpiration=DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 1 HOUR) WHERE id=?', undef, $id);
		} else {
			$dbh->do('UPDATE dontprintwebaccounts SET failedtries=1, failureexpiration=DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 1 HOUR) WHERE id=?', undef, $id);
		}
		err(3, 'Username or password incorrect.');
	}
	
	return $id;
}


sub checkLoginAndGetUserId {
	my $cgi = $_[0];
	$dbh = $_[1];  # global on purpose
	my $loginmethod = $cgi->param('login');
	my $id;

	if ($loginmethod eq 'fb') {
		$id = checkFbAccessToken($cgi->param('accessToken'));
	} elsif ($loginmethod eq 'username') {
		$id = checkPassword($cgi->param('username'), $cgi->param('password'));
	} else {
		err(1, 'Login method not supported.');
	}
	
	if (not defined $id) {
		err(2, 'Authentication error.');
	}
	return $id;
}


1;
