#!/usr/bin/perl
##
#	dkim_verify.pl	Sample script for understanding dkim verify
#
#	
#
#
use strict;
use warnings;
use utf8;

use Net::DNS;
use Data::Dumper;

use lib "./";
use dp;			# debug print module

dp::dp_mode(0);	# 0:set quiet, 1: set verbose

#	set dirs 
my $working_dir = "./working";

#	set sample mails
my $mfile = "";
my $email_dir = "/mnt/c/temp";
my	@sample_mails = (
	"$email_dir/iij-email.txt",		# 0
	"$email_dir/smbc1.txt",			# 1
	"$email_dir/nikkei01.txt",	 	# 2 Verify Success
	#"$email_dir/sample3.txt",
);
my $samples = $#sample_mails;

#	Woring files
my $hash_target_f = "$working_dir/hash_target.txt";
my $body_hash_f = "$working_dir/mail_body_canonical.txt";
my $mail_body_f = "$working_dir/mail_body.txt";
my $pub_key_f = "$working_dir/pub_key.pem";
my $sig_f = "$working_dir/sig.sig";

#
#	Argument handling
#
for(@ARGV){
	if(-f $_){
		$mfile = $_;
	}
	elsif(/[\d+]$/){
		if($_ > $samples){
			die "sample mails 0-$samples\n";
		}
		$mfile = $sample_mails[$_];
	}
}
if(! $mfile){
	die "ERROR: usage: dkim_verify email_faile || 0-$samples\n";
}

#
#	Perse Mail header and body
#
my $rn = 0;		# Record number for debug
my ($main_headers, $mail_body) = &mail_header($mfile);			# get mail header information from mail
my $dkim_rec = &find_record("DKIM-Signature", $main_headers);	# get DKIM signature
# die "NO dkim definition\n" if(scalar(@$dkim_rec) <= 0);		# leaving it for debugging
&gen_file($mail_body, $mail_body_f);							# create mail body file

#
#	calc Mail Body hash
#
my $canonical = [];												# get canonical mail body for calc hash
foreach my $s (split(/\r\n/, $mail_body)){
		$s = &normailzation($s);
		push(@$canonical, $s);
}
&remove_last_blank_lines($canonical);							# remove blank lines at last
my $canonical_body = join("\r\n", @$canonical) . "\r\n";		# gen canonical mail body string
#$canonical_body =~ s/[\r\n]+$//;		# remove DKIM-signature
&gen_file($canonical_body, $body_hash_f);						# create canoncal mail body file

my $bh = `cat $body_hash_f | openssl dgst -sha256 -binary | base64`;	# get hash of canoncal mail body
chop($bh);

#
#	Parse DKIM-Signature in Mail Header
#
my $dkim_info = &dkim_info($dkim_rec->[0]);	# set dkim signature record (string)
#foreach my $k (keys %$dkim_info){			# dump dkim parameters
#	dp::dp join(": ", $k, $dkim_info->{$k}) . "\n";
#}
my $dkim_fqdn = join(".", $dkim_info->{s}//"#", "_domainkey", $dkim_info->{d}//"#");	# set dkim dns FQDN
dp::dp "\n";
dp::dp "DKIM_FQDN: $dkim_fqdn" . "\n";

#	Get DKIM Hash Headers
my @hash_headers = split(/:/, $dkim_info->{h}//"");
if($#hash_headers < 0){
	die "NO dkim header list (h=)\n";
}
dp::dp "bh in mail: " . $dkim_info->{bh} . "\n";
dp::dp "bh by calc: " . $bh . "\n";
if($bh eq $dkim_info->{bh}){
	dp::dp "body hash (bh) OK\n";
}
else {
	dp::dp "body hash (bh) Failer\n";				# may be better to exit as error here
}
dp::dp "\n";

#
#	Get DKIM Public information from DKIM DNS Server
#
my $dkim_dns_info = &get_dkim_pub($dkim_fqdn);		# get dkim public information from dkim DNS server
my $pub_key = "-----BEGIN PUBLIC KEY-----\n" .
			 $dkim_dns_info->{p} . "\n" . 
			"-----END PUBLIC KEY-----\n";			# set DKIM Public key
dp::dp "pub_key from DNS: " . $dkim_dns_info->{p} . "\n";

#
#	calc signature
#

#	reconstract headear data (hash_target)
$canonical = [];
my $dkimf = 0;
foreach	my $h (@hash_headers, "dkim-signature"){	# convine dkim target headers and dkim-signature
	my $mh_rec = &find_record($h, $main_headers);	# get target mail header
	#dp::dp "## " . scalar(@$mh_rec). ": " . $h . "\n";
	
	foreach my $s (@$mh_rec){
		$s = lc($h) . ":" . &normailzation($s);		# little character header and canonicaled value
		if($h eq "dkim-signature"){
			$s =~ s/b=.*=/b=/;						# remove dkim 'b' 
		}
		push(@$canonical, $s);
	}
}	
&remove_last_blank_lines($canonical);				# remove blank lines at last
my $hash_target = join("\r\n", @$canonical);
&gen_file($hash_target, $hash_target_f);			# create hash target file

&gen_file($pub_key, $pub_key_f);					# create public key (from DNS)
my $sig = $dkim_info->{b};							# create sig file
$sig =~ s/ //g;										# remove spaces from sig
&gen_file($sig, "$sig_f.b64");						# sig file base64 -> binary
my $cmd = "base64 -d $sig_f.b64 > $sig_f";	
##dp::dp $cmd . "\n";
system($cmd);										# create binary sig file

#
# verify sig and hash_target
#
dp::dp "signature in mail: " . $dkim_info->{b} . "\n";
$cmd = "openssl dgst -sha256 -verify $pub_key_f -signature $sig_f $hash_target_f";
dp::dp "Verify Signature: $cmd\n";
my $b = `$cmd`;								# Verified OK | Verified Failed
if($b =~ /OK/){
	dp::dp $b . "\n";		# Verify OK
}
else {
	dp::dp $b . "\n";		# Verify Failed
}

exit;

#######################################

#
#	Remove last blank lines
#
sub	remove_last_blank_lines
{
	my($canonical) = @_;

	for(my $i = scalar(@$canonical-1); $i >= 0; $i--){
		#dp::dp "#### $i: " . $canonical->[$i] . "####\n";
		last if($canonical->[$i]);

		pop(@$canonical);	# remove blank line at end of the body
	}
}

#
#	Gen $file contains $str
#
sub	gen_file
{
	my ($str, $file) = @_;

	open(FD, "> $file") || die "cannot create $file";
	print FD $str ;
	close(FD);
}

#
#	Normalization 
#
sub	normailzation
{
	my($s) = @_;

	$s =~ s/[\r\n]+$//;	# remove CR LF
	$s =~ s/\s+$//;		# remove spaces at end of line
	$s =~ s/\s+/ /g;	# combine spaces to a space
	return $s;
}

#
#	(@$headers, $body) = &mail_header(maile_body_file_name);
#	@headers:  [[r,v],[r,v]];
#	$body: mail body
#
sub	mail_header
{
	my ($fn) = @_;

	my $headers = [];

	my $body_f = "";
	my $body = "";
	my $rec = "";
	my $header = [];
	open(FD, $mfile) || die "cannot open $mfile";
	while(<FD>){
		if($body_f){
			$body .= $_;
			next;
		}

		s/[\r\n]+$//;
		if((! $body_f) && $_ eq ""){
			$body_f = 1;
		}
		elsif(/^\s/){
			s/^\s+/ /;	# ????
			$rec .= $_;
		}
		else {
			if($rec){
				my ($k, $v) = &entry_record($rec);
				push(@$headers, [$k, $v]);
				#dp::dp "$rec\n";
			}
			$rec = $_;
		}
	}
	if($rec){
		my ($k, $v) = &entry_record($rec);
		push(@$headers, [$k, $v]);
		#dp::dp "$rec\n";
	}
	close(FD);
	

	return ($headers, $body);
}

#
#	$records = &find_record($target, $headers);
#		$target: record name
#		@$headers: array generated by &mail_header()
#	@$reords: mached records;
#
sub 	find_record
{
	my ($target, $headers) = @_;

	my $hit = [];

	my $i = 0;

	foreach my $a (@$headers){
		my ($k, $v) = @$a;
		#dp::dp "$i $target:$k\n";
		if($k =~ /^$target$/i){
			#dp::dp "HIT!\n";
			push(@$hit, $v);
		}
		$i++;
	}
	return $hit;
}

#
#	$dkim_rec = &dkim_info($record);
#		$record: dkim record
#	%$dkim_rec = {p1 => v1, p2 => v2, .....}
#
sub	dkim_info
{
	my ($record) = @_;

	my $dkim_rec = {};

	return $dkim_rec if(!$record);

	foreach my $rec (split(/; */, $record)){
		$rec =~ /^(\w+)=/;
		my $k = $1;
		next if(!$k);

		$rec =~ s/$k=//;
		$dkim_rec->{$k} = $rec;
	}
	return $dkim_rec;
}


#
#	($k, $v) = &entry_record($rec);
#		$rec: "MailHead: xxxxxxxxx"
#
sub	entry_record
{
	my ($rec) = @_;
	#dp::dp "\n$rn *** $rec***\n";
	$rn++;

	$rec =~ /^([\w-]+):\s*(.+)$/;
	my $k = $1//"###";
	$rec =~ s/$k:\s*//;
	my $v = $rec//"---";
	#my ($k, $v) = ($1//"###", $2//"---");
	#dp::dp $k . "\n";
	#dp::dp " " .  $v . "\n";
	return($k, $v);
}

#
#	$dkim_info = &get_dkim_pub($dkim_fqdn);
#		$dkim_fqdn: FQDN of domain key DNS server (ex. s-dkim-key01._domainkey.dn.smbc.co.jp)
#	%$dkim_info: {k1 => v1, k2 => v2, .....}
#
sub	get_dkim_pub
{
	my ($dkim_fqdn) = @_;

	my $dkim = {};
	my @dns_ans = rr($dkim_fqdn, "TXT");	# get txt information from DKIM dns
	
	foreach my $r (@dns_ans){
		#dp::dp "\n";
		#dp::dp Dumper $r;
		#dp::dp "-" x 20 . "\n";

		my $record = $r->{txtdata}->[0]->[0] //"";
		# v=DKIM1; h=sha256; g=*; k=rsa; p=MIGfMA0GCSqGSIb3DQEBA..... '
		if($record){
			foreach my $rr (split(/; */, $record)){
				my($k, $v) = split(/=/, $rr);
				$dkim->{$k} = $v;
			}
		}
	}
	return $dkim;
}
exit;
