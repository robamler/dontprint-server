#!/usr/bin/perl

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


# Allow only POST request to avoid accidential e-mail sending due to page reload

if ($ENV{'REQUEST_METHOD'} ne 'POST') {
	err(4, 'Only POST requests allowed.');
}


# Get query parameters

my @params = {};
foreach my $pair (split /[&;]/, $ENV{'QUERY_STRING'}) {
	my ($k, $v) = split '=', $pair, 2;
	$v =~ s/\+/\ /g;
	$v =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
	$params{$k} = $v;
}


# Canonicalize e-mail address and calculate id
my $mail = $params{'email'};
$mail =~ s/^\s+|\s+$//g;
my $id = canonicalizeAndObfuscateEmail($mail);
if (not defined $id) {
	err(1, 'Invalid e-mail address.');
}


# Check if email is verified

my $dbh = DBI->connect('DBI:mysql:dontkqlm_productiondb', '__DBUSERNAME__', '__DBPASSWORD__'
	           ) || err(2, 'Could not connect to database.');

my $verified = $dbh->do('UPDATE verifiedemails SET usecount=usecount+1 WHERE id=?', undef, $id);
if (not defined $verified or $verified < 0.5) {
	err(3, 'Email-address not verified.');
}

$dbh->disconnect();


# Send email

my $itemKey = $params{'itemKey'};
my $filename = $params{'filename'};
my $filesize = $ENV{'CONTENT_LENGTH'};
my @sizeunits = ('bytes', 'KiB', 'MiB');
my $sizeindex;
for ($sizeindex=0; $sizeindex<(scalar @sizeunits)-1 && $filesize>=999.5; $sizeindex++) {
	$filesize /= 1024;
}
$filesize = sprintf("%.1f", $filesize) . ' ' . $sizeunits[$sizeindex];

$msg = MIME::Lite->new (
	From    => 'noreply@dontprint.net',
	To      => $mail,
	Subject => "Dontprint is sending this document to your e-reader ($itemKey)",
	Type    => 'multipart/mixed'
) or err(5, 'Error creating email container');

$msg->attach (
	Type => 'TEXT',
	Data => "With this e-mail, Dontprint is sending the attached
document to your e-reader.

File name: $filename
File size: $filesize
E-reader address: $mail

-- 
Dontprint -- paperless printer for scientists
www.dontprint.net"
) or err(6, 'Error creating text part of email');

$msg->attach (
	Type        => 'application/pdf',
	FH          => STDIN,
	Filename    => $filename,
	Disposition => 'attachment'
) or err(7, 'Error attaching PDF file to email');

$msg->send or err(8, 'Error sending email');


# Return success status

print "{\"success\":true,\"returncode\":0,\"message\":\"Document sent successfully.\",\"filesize\":\"$filesize\"}";

