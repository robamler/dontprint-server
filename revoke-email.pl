#!/usr/bin/perl

use CGI;
use Email::Valid;
use Digest::SHA qw(hmac_sha1);
use DBI;

sub err {
	print "{\"success\":false,\"errno\":$_[0],\"message\":\"$_[1]\"}";
	if (defined $dbh) {
		$dbh->disconnect();
	}
	exit;
}


# Checks that the parameter is a valid e-mail address and
# calculates an hmac of a canonicalized form of the email.
sub canonicalizeAndObfuscateEmail {
	$mail = lc($_[0]);
	if (Email::Valid->address($mail)) {
		return hmac_sha1($mail, 'dontprint-generic-salt');
	} else {
		return undef;
	}
}


print "Content-Type: application/json\n\n";


# Canonicalize e-mail address and calculate id
my $cgi = new CGI;
my $mail = $cgi->param('email');
my $code = $cgi->param('code');

$mail =~ s/^\s+|\s+$//g;
my $id = canonicalizeAndObfuscateEmail($mail);
if (not defined $id) {
	err(1, 'Invalid e-mail address.');
}
if ((not defined $code) or (length($code) != 4)) {
	err(2, 'The revocation code must be a sequence of four digits.');
}


# Connect to database

my $dbh = DBI->connect('DBI:mysql:dontkqlm_productiondb', '__DBUSERNAME__', '__DBPASSWORD__'
	           ) || err(2, 'Could not connect to database.');


# Check if email is verified

my $sth = $dbh->prepare('SELECT 1 FROM verifiedemails WHERE id=?');
$sth->execute($id);
my $ret = $sth->fetchrow_arrayref();
if (not defined $ret) {
	print '{"success":true,"returncode":1,"message":"The email address had already been deleted from our database."}';
	$dbh->disconnect();
	exit;
}


# Get pending revocation request for this e-mail address
$sth = $dbh->prepare('SELECT numtries,code FROM pendingrevocations WHERE id=? AND timestamp > DATE_ADD(CURRENT_TIMESTAMP, INTERVAL -1 DAY)');
$sth->execute($id);
$result = $sth->fetchrow_arrayref();
if (not defined $result) {
	err(4, 'The revocation code has expired. Consider requesting a new code.');
}

if ($result->[0] >= 3) {
	err(5, 'Too many failed attempts. Please try again in 24 hours.');
}

if ($result->[1] ne $code) {
	$dbh->do('UPDATE pendingrevocations SET numtries=numtries+1 WHERE id=?', undef, $id);
	err(6, 'Wrong revocation code.');
}


# Revocation code is valid
$dbh->do('DELETE FROM pendingrevocations WHERE id=?', undef, $id);
$dbh->do('DELETE FROM verifiedemails WHERE id=?', undef, $id);

print '{"success":true,"returncode":0,"message":"Email deleted from our database."}';


$dbh->disconnect();


