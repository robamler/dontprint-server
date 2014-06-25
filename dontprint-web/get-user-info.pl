#!/usr/bin/perl

use CGI;
use DBI;
use JSON;
use DontprintWeb;



print "Content-Type: application/json\n\n";

my $cgi = new CGI;
my $dbh = DBI->connect('DBI:mysql:dontkqlm_productiondb', '__DBUSERNAME__', '__DBPASSWORD__'
	           ) || err(10, 'Could not connect to database.');
my $id = checkLoginAndGetUserId($cgi, $dbh);


# Get user data from database

my $sth = $dbh->prepare('SELECT ereaderemail, emailverified FROM dontprintwebaccounts WHERE id=?');
$sth->execute($id);
my $ret = $sth->fetchrow_arrayref();
$dbh->disconnect();

if (not defined $ret) {
	print '{"success":true,"ereaderEmail":"","emailVerified":false}';
	exit;
} else {
	$response = {
		'success' => JSON::true,
		'ereaderEmail' => $ret->[0],
		'emailVerified' => $ret->[1] ? JSON::true : JSON::false
	};
	print encode_json($response);
	exit;
}
