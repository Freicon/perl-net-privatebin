use strict;
use warnings;
use lib "./lib/";
use MIME::Base64;
use File::Basename;
use File::Spec;
use Net::PrivateBin;

my $client = Net::PrivateBin->new(
    url => 'https://pastebin.url.net/',
    compression => 'zlib',
    formatter => 'plaintext',
    # debug => 1,
);

$client->set_password("123456");

# 1 skips https validation
my $result = $client->get_and_decode("/?821d5f711111111704#HnwhgtUCunoesqqqqqqyJzQpDhMATfbif3MrosSmH2CXiW", 1);

{
use Data::Dumper;
$Data::Dumper::Terse = 1;
print STDERR Dumper "\n" . 'Typ: ' . (ref \$result) . ' - Variable: $result  --- ' . +(split'\/', __FILE__)[-1] . ':' . __LINE__;
print STDERR Dumper \$result;
print STDERR Dumper '----------------------------------- END $result -----------------------------------';
$Data::Dumper::Terse = 0;
}
