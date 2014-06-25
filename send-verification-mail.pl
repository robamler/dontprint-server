#!/usr/bin/perl

use CGI;
use Email::Valid;
use Digest::SHA qw(hmac_sha1);
use DBI;
use MIME::Lite;

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
$mail =~ s/^\s+|\s+$//g;
my $id = canonicalizeAndObfuscateEmail($mail);
if (not defined $id) {
	err(1, 'Invalid e-mail address.');
}


# Connect to database

my $dbh = DBI->connect('DBI:mysql:dontkqlm_productiondb', '__DBUSERNAME__', '__DBPASSWORD__'
	           ) || err(2, 'Could not connect to database.');


# Check if email is already verified

my $sth = $dbh->prepare('SELECT 1 FROM verifiedemails WHERE id=?');
$sth->execute($id);
my $ret = $sth->fetchrow_arrayref();
if (defined $ret) {
	print '{"success":true,"returncode":1,"message":"The email address is already verified. You can go ahead and use Dontprint right away."}';
	$dbh->disconnect();
	exit;
}


# Check if IP address exceeds verification requests

my $ipaddress = $ENV{'REMOTE_ADDR'};
$sth = $dbh->prepare('SELECT count FROM verificationrequests WHERE ipaddress=? AND timestamp > DATE_ADD(CURRENT_TIMESTAMP, INTERVAL -5 MINUTE)');
$sth->execute($ipaddress);
my $result = $sth->fetchrow_arrayref();
if (not defined $result) {
	$dbh->do('INSERT INTO verificationrequests (ipaddress,count) VALUES (?,1) ON DUPLICATE KEY UPDATE count=1, timestamp=CURRENT_TIMESTAMP', undef, $ipaddress);
} else {
	if ($result->[0] >= 20) {
		err(3, 'Too many verification mails requested from your IP address. Please wait for 5 minutes and then try again.');
	} else {
		$dbh->do('UPDATE verificationrequests SET count=count+1 WHERE ipaddress=?', undef, $ipaddress);
	}
}


# Check if there is already a pending verification request for this e-mail address
$sth = $dbh->prepare('SELECT nummails,code FROM pendingverifications WHERE id=? AND timestamp > DATE_ADD(CURRENT_TIMESTAMP, INTERVAL -1 DAY)');
$sth->execute($id);
$result = $sth->fetchrow_arrayref();
my $code;
if (not defined $result) {
	# Generate new random code; don't use the digit 0 to avoid confusion with the letter O
	$code = (int(rand(9))+1) . (int(rand(9))+1) . (int(rand(9))+1) . (int(rand(9))+1);
	$dbh->do('INSERT INTO pendingverifications (id,code) VALUES (?,?) ON DUPLICATE KEY UPDATE nummails=1, numtries=0, code=?, timestamp=CURRENT_TIMESTAMP', undef, $id, $code, $code)
} else {
	if ($result->[0] >= 3) {
		err(4, 'Dontprint already sent 3 verification emails to this address within the last 24 hours. Please make sure that you entered the correct email address, that you added the address \"noreply@dontprint.net\" to the list of approved sender addresses for your e-reader, and that the e-mails haven\'t arrived yet. It may take a few minutes before the emails arrive on your device and you may have to manually initiate the synchronization process on your e-reader.');
	} else {
		$dbh->do('UPDATE pendingverifications SET nummails=nummails+1 WHERE id=?', undef, $id);
		$code = $result->[1];
	}
}


# Disconnect from database
$dbh->disconnect();


# Generate PDF

my $pdfdata;

open(MEMORY, '>', \$pdfdata) or err(4, 'Can\'t open memory file');

open(PART1, '<', 'verification-pdf-part1');
print MEMORY <PART1>;
close(PART1);

print MEMORY $code;

open(PART2, '<', 'verification-pdf-part2');
print MEMORY <PART2>;
close(PART2);

close(MEMORY);


# Send verification code

$msg = MIME::Lite->new (
	From    => 'noreply@dontprint.net',
	To      => $mail,
	Subject => "Dontprint e-mail verification code $code",
	Type    => 'multipart/mixed'
) or err(5, 'Error creating email container');

$msg->attach (
	Type => 'TEXT',
	Data => "Dear Dontprint user,

Your verification code for this e-mail address is $code.

Use this code to to proof to Dontprint that you own the
e-mail address $mail.

For further instructions, please refer to the attached
PDF document.

Yours sincerely,
Robert Bamler

-- 
Dontprint -- paperless printer for scientists
www.dontprint.net"
) or err(6, 'Error creating text part of email');

$msg->attach (
	Type => 'application/pdf',
	Data => $pdfdata,
	Filename => "dontprint-verification-code-$code.pdf",
	Disposition => 'attachment'
) or err(7, 'Error attaching PDF file to email');

$msg->send or err(8, 'Error sending email');


# Return success status

print '{"success":true,"returncode":0,"message":"A document with the verification code was sent to your e-reader."}';

