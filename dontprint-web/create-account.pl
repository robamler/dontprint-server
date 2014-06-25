#!/usr/bin/perl

use CGI;
use DBI;
use DontprintWeb;
use Digest::SHA qw(hmac_sha256);


print "Content-Type: application/json\n\n";

my $cgi = new CGI;
my $dbh = DBI->connect('DBI:mysql:dontkqlm_productiondb', '__DBUSERNAME__', '__DBPASSWORD__'
	           ) || err(10, 'Could not connect to database.');


# Check formal validity of username and password

my $username = $cgi->param('username');
my $id = "$username username";
my $password = $cgi->param('password');

if (not $username =~ /^[\w\p{L}\p{N}\p{M}.-@+][\w\p{L}\p{N}\p{M}.-@+ ]{2,30}[\w\p{L}\p{N}\p{M}.-@+]$/) {
	err(11, 'Invalid username');
}

if (length($password) < 4 or length($passw) > 40) {
	err(12, 'Invalid password');
}


# Check if username exists already

my $sth = $dbh->prepare('SELECT id FROM dontprintwebaccounts WHERE id=?');
$sth->execute($id);
my $ret = $sth->fetchrow_arrayref();

if (defined $ret) {
	err(13, 'Username already exists.');
}


# Generate salt

@chars = ('A'..'Z', 'a'..'z', '0'..'9');  # "my"-keyword doesn't work here
my $salt = '';
$salt .= $chars[rand @chars] for 1..10;
my $saltedpassword = hmac_sha256($password, $salt);


# Save user in database

$dbh->do('INSERT INTO dontprintwebaccounts (id, salt, saltedpassword, failedtries, failureexpiration, ereaderemail, emailverified) VALUES (?,?,?,0,CURRENT_TIMESTAMP,"",0)?', undef, $id, $salt, $saltedpassword);

$dbh->disconnect();


# Send default user info back to client

print '{"success":true,"ereaderEmail":"","emailVerified":false}';
