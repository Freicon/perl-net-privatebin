use strict;
use warnings;
use Net::PrivateBin;

my $client = Net::PrivateBin->new(
    url => 'https://pastebin.url.net/',
    compression => 'none',
    formatter => 'plaintext',
    # debug => 1,
);

$client->set_text("Hallo das ist mein Text");
$client->set_password("123456");
$client->set_burn(1);
$client->set_compression("zlib");
$client->set_expire("5min");
$client->set_formatter("plaintext");
$client->set_attachment("<Path to file>");

# 1 skips https validation
my $result = $client->encode_and_post(1);

print "Paste URL: " . $result->{url} . "\n";
