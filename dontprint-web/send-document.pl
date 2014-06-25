#!/usr/bin/perl

use JSON;
use CGI;
use DBI;
use DontprintWeb;
use MIME::Lite;
require LWP::UserAgent;


print "Content-Type: application/json\n\n";


# Allow only POST request to avoid accidential e-mail sending due to page reload

if ($ENV{'REQUEST_METHOD'} ne 'POST') {
	err(11, 'Only POST requests allowed.');
}


# Login

my $cgi = new CGI;
my $dbh = DBI->connect('DBI:mysql:dontkqlm_productiondb', '__DBUSERNAME__', '__DBPASSWORD__'
	           ) || err(10, 'Could not connect to database.');
my $id = checkLoginAndGetUserId($cgi, $dbh);


# Check if email is verified

my $sth = $dbh->prepare('SELECT ereaderemail, emailverified FROM dontprintwebaccounts WHERE id=?');
$sth->execute($id);
my $ret = $sth->fetchrow_arrayref();
$dbh->disconnect();

if (not defined $ret or not $ret->[1]) {
	err(13, 'Email address not verified.');
}

my $mail = $ret->[0];


# Download file

my $pdfurl = $cgi->param('pdfurl');
if (not $pdfurl =~ /^http\:\/\/arxiv\.org\/pdf\/[0-9.v]+\/?$/) {
	err(14, 'Requested URL not allowed.');
}
my $ua = LWP::UserAgent->new;
$ua->env_proxy;
# $ua->agent('Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:30.0) Gecko/20100101 Firefox/30.0');

my $response = $ua->get($pdfurl);
if (not $response->is_success) {
	err(15, 'Unable to download file');
}
my $pdfdata = $response->content();


# Send email

my $itemKey = $cgi->param('identifier');
my $filename = $cgi->param('filename');
my $filesize = length($pdfdata);
my @sizeunits = ('bytes', 'KiB', 'MiB');
my $sizeindex;
for ($sizeindex=0; $sizeindex<(scalar @sizeunits)-1 && $filesize>=999.5; $sizeindex++) {
	$filesize /= 1024;
}
$filesize = sprintf("%.1f", $filesize) . ' ' . $sizeunits[$sizeindex];

$msg = MIME::Lite->new (
	From    => 'noreply@dontprint.net',
	To      => $mail,
	Subject => "Dontprint-web is sending this document to your e-reader ($itemKey)",
	Type    => 'multipart/mixed'
) or err(16, 'Error creating email container');

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
) or err(17, 'Error creating text part of email');

$msg->attach (
	Type        => 'application/pdf',
	Data        => $pdfdata,
	Filename    => $filename,
	Disposition => 'attachment'
) or err(18, 'Error attaching PDF file to email');

$msg->send or err(19, 'Error sending email');


# Return success status

print encode_json({
	'success' => JSON::true,
	'returncode' => 0,
	'message' => 'Document sent successfully.',
	'filesize' => $filesize,
	'ereaderEmail' => $mail
});
