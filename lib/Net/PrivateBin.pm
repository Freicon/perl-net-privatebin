package Net::PrivateBin;

use strict;
use warnings;
use Carp;
use URI;
use JSON::XS;
use LWP::UserAgent;
use MIME::Base64;
use Crypt::PRNG qw(random_bytes);
use Crypt::PBKDF2;
use Crypt::AuthEnc::GCM;
use Crypt::Misc ':all'; # encode_b58b
use Compress::Raw::Zlib;
use HTTP::Request::Common qw(POST);
use Encode;

our $VERSION = '0.01';

# Constructor to initialize a new Net::PrivateBin object
sub new {
    my ($class, %args) = @_;

    # remove trailing slash
    my $url = $args{url};
    $url =~ s:/$::;

    my $self = {
        url             => $url,
        compression     => $args{compression} || 'zlib',
        formatter       => $args{formatter} || 'plaintext',
        attachment      => undef,
        attachment_name => undef,
        password        => undef,
        expire          => $args{expire} || '1day',
        discussion      => $args{discussion} || 0,
        burn            => $args{burn} || 1,
        url_separator   => "#-",
        text            => '',
        debug           => $args{debug} || 0,
        ua              => LWP::UserAgent->new,
    };

    bless $self, $class;
    return $self;
}

# Set the password used for encryption
sub set_password {
    my ($self, $password) = @_;
    $self->{password} = $password;
}

# Set the URL for the PrivateBin server
sub set_url {
    my ($self, $url) = @_;

    # remove trailing slash
    $url =~ s:/$::;
    $self->{url} = $url;
}

# Set the formatter type with validation
sub set_formatter {
    my ($self, $formatter, $bypass) = @_;
    my @valid_values = qw(plaintext syntaxhighlighting markdown);
    croak "Invalid formatter" if (!$bypass && !grep {$_ eq $formatter} @valid_values);
    $self->{formatter} = $formatter;
}

# Set the attachment file to be uploaded
sub set_attachment {
    my ($self, $file_location, $filename) = @_;
    open my $fh, '<', $file_location or croak "Can't open file: $!";
    binmode $fh;
    my $file = do {
        local $/;
        <$fh>
    };
    close $fh;

    my $mime = `file --mime-type -b $file_location`; # Get MIME type via system call
    chomp($mime);
    $mime = "application/octet-stream" unless $mime;
    my $data = 'data:' . $mime . ';base64,' . encode_base64($file, '');
    my $name = $filename // (split('/', $file_location))[-1];

    $self->{attachment} = $data;
    $self->{attachment_name} = $name;
}

# Set the text to be uploaded
sub set_text {
    my ($self, $text) = @_;
    $self->{text} = $text;
}

# Set the compression method with validation
sub set_compression {
    my ($self, $compression) = @_;
    my @valid_values = qw(zlib none);
    croak "Unknown compression type, (zlib or none)..." unless grep {$_ eq $compression} @valid_values;
    $self->{compression} = $compression;
}

# Enable or disable discussion for the paste
sub set_discussion {
    my ($self, $discussion) = @_;
    if ($discussion && $self->{burn}) {
        $self->{burn} = 0;
    }
    $self->{discussion} = $discussion;
}

# Enable or disable burn after reading for the paste
sub set_burn {
    my ($self, $burn) = @_;
    if ($burn && $self->{discussion}) {
        $self->{discussion} = 0;
    }

    if (!$burn) {
        $self->{url_separator} = "#";
    } else {
        $self->{url_separator} = "#-";
    }
    $self->{burn} = $burn;
}

# Enable or disable debug mode
sub set_debug {
    my ($self, $debug) = @_;
    $self->{debug} = $debug;
}

# Set the expiration time for the paste with validation
sub set_expire {
    my ($self, $expire, $bypass) = @_;
    my @valid_values = qw(5min 10min 1hour 1day 1week 1month 1year never);
    croak "Invalid expire value" if (!$bypass && !grep {$_ eq $expire} @valid_values);
    $self->{expire} = $expire;
}

# Compress the paste data using zlib
sub _compress_paste {
    my ($self, $paste_data) = @_;
    my ($deflate, $status) = new Compress::Raw::Zlib::Deflate(
        -WindowBits => -Compress::Raw::Zlib::MAX_WBITS
    );

    my $output;
    $status = $deflate->deflate($paste_data, $output);
    $status = $deflate->flush($output);

    return $output;
}

# Encode the paste data for submission
sub encode_paste {
    my $self = shift;
    my $nonce = random_bytes(16);
    my $salt = random_bytes(8);
    my $paste_key = random_bytes(32);

    my $b58 = encode_b58b($paste_key);

    my $auth_data = [ [
        encode_base64($nonce, ""), encode_base64($salt, ""), 100000, 256, 128, 'aes', 'gcm', $self->{compression}
    ], $self->{formatter}, $self->{discussion}, $self->{burn} ];

    my $paste_passphrase = $self->{password} ? ($paste_key . $self->{password}) : $paste_key;

    my $pbkdf2 = Crypt::PBKDF2->new(
        hasher     => Crypt::PBKDF2->hasher_from_algorithm('HMACSHA2', 256),
        iterations => 100000,
        output_len => 32
    );

    my $key = $pbkdf2->PBKDF2($salt, $paste_passphrase);

    my $paste_data = $self->_get_paste_data();

    my $paste = $self->{compression} eq "zlib" ? $self->_compress_paste($paste_data) : $paste_data;

    my $gcm = Crypt::AuthEnc::GCM->new('AES', $key);
    $gcm->iv_add($nonce);
    $gcm->adata_add(encode_json($auth_data));

    my $ciphertext = $gcm->encrypt_add($paste);
    my $tag = $gcm->encrypt_done();

    my $data = {
        v     => 2,
        adata => $auth_data,
        ct    => encode_base64($ciphertext . $tag, ""),
        meta  => {
            expire           => $self->{expire}
        },
    };

    if ($self->{debug}) {
        print "Debugging information:\n";
        print "Base58 Hash: $b58\n";
        print "Paste Data: $paste_data\n";
        print "Auth Data: ", join(", ", @$auth_data), "\n";
        print "Key: ", encode_base64($key, ""), "\n";
        print "CipherText: ", encode_base64($ciphertext, ""), "\n";
        print "CipherTag: ", encode_base64($tag, ""), "\n";
        print "Post Data: ", encode_base64($data, ""), "\n";
    }

    return {
        data => $data,
        b58  => $b58,
    };
}

# Prepare paste data in JSON format
sub _get_paste_data {
    my $self = shift;
    my $paste_data = { paste => $self->{text} };
    if ($self->{attachment}) {
        $paste_data->{attachment} = $self->{attachment};
        $paste_data->{attachment_name} = $self->{attachment_name};
    }
    return encode_json($paste_data);
}

# Post the encoded data to the PrivateBin server
sub post_paste {
    my ($self, $data, $disable_ssl_verification) = @_;
    
    # Check if the URL is set
    croak "No URL set for posting data" unless $self->{url};

    my $encoded_data = encode_json($data->{data});
    $encoded_data =~ s/,"([01])","([01])"]/,$1,$2]/;

    my $req = POST $self->{url} . "/",
        Content_Type       => 'application/json',
        'X-Requested-With' => 'JSONHttpRequest',
        Content            => $encoded_data;

    # Disable SSL certificate verification if requested
    if ($disable_ssl_verification) {
        $self->{ua}->ssl_opts(verify_hostname => 0);
        $self->{ua}->ssl_opts(SSL_verify_mode => 0x00);
    }

    my $res = $self->{ua}->request($req);

    if ($res->is_success) {
        my $result = decode_json($res->content);
        if ($self->{debug}) {
            print "Response: ", $res->content, "\n";
        }

        if ($result->{status} != 0) {
            croak "PrivateBin request was not successful: " . $result->{message}
        }

        return {
            requests_result => $result,
            b58             => $data->{b58},
            url             => $self->{url} . $result->{url} . $self->{url_separator} . $data->{b58}
        };
    } else {
        croak "Failed to post data: " . $res->status_line;
    }
}

# Method to retrieve a paste from the PrivateBin server
sub get_paste {
    my ($self, $paste_id, $disable_ssl_verification) = @_;

    # Check if URL is set
    croak "No URL set for retrieving paste" unless $self->{url};

    # Disable SSL certificate verification if requested
    if ($disable_ssl_verification) {
        $self->{ua}->ssl_opts(verify_hostname => 0);
        $self->{ua}->ssl_opts(SSL_verify_mode => 0x00);
    }

    # remove leading /?
    $paste_id =~ s:^/?\??::;

    # Create a GET request to fetch the paste data
    my $req = HTTP::Request->new(GET => "$self->{url}/?$paste_id");
    $req->header('X-Requested-With' => 'JSONHttpRequest');

    my $res = $self->{ua}->request($req);

    if ($res->is_success) {
        my $result = decode_json($res->content);
        if ($self->{debug}) {
            print "Retrieved paste: ", $res->content, "\n";
        }
        return $result;
    } else {
        croak "Failed to retrieve paste: " . $res->status_line;
    }
}

# Method to decrypt the retrieved paste
sub decode_paste {
    my ($self, $paste_data, $password) = @_;

    # Extract key, nonce, and auth_data from paste_data
    my $nonce = decode_base64($paste_data->{adata}[0][0]);
    my $salt = decode_base64($paste_data->{adata}[0][1]);
    my $iterations = $paste_data->{adata}[0][2];
    my $key_length = $paste_data->{adata}[0][3];
    my $tag_length = $paste_data->{adata}[0][4];
    my $cipher = $paste_data->{adata}[0][5];
    my $mode = $paste_data->{adata}[0][6];
    my $compression = $paste_data->{adata}[0][7];

    if ($cipher ne "aes" || $mode ne "gcm") {
        croak "Cipher or mode not supported";
    }

    # Generate the key using the password and salt
    my $pbkdf2 = Crypt::PBKDF2->new(
        hasher     => Crypt::PBKDF2->hasher_from_algorithm('HMACSHA2', 256),
        iterations => $iterations,
        output_len => $key_length / 8
    );

    my $derived_key = $pbkdf2->PBKDF2($salt, $password);

    # Decode the Base64 encoded ciphertext
    my $ciphertext = decode_base64($paste_data->{ct});

    # Extract the actual encrypted data and the authentication tag
    my $tag = substr($ciphertext, -($tag_length / 8));
    my $encrypted_data = substr($ciphertext, 0, length($ciphertext) - ($tag_length / 8));

    # Initialize GCM mode with the derived key
    my $gcm = Crypt::AuthEnc::GCM->new('AES', $derived_key);
    $gcm->iv_add($nonce);
    $gcm->adata_add(encode_json($paste_data->{adata}));

    # Decrypt the data
    my $decrypted_data = $gcm->decrypt_add($encrypted_data);
    if (!$gcm->decrypt_done($tag)) {
        croak "Failed to verify authentication tag, data might be corrupted or tampered";
    }

    # Decompress if necessary
    if ($compression eq 'zlib') {
        my ($inflate, $status) = Compress::Raw::Zlib::Inflate->new(-WindowBits => -Compress::Raw::Zlib::MAX_WBITS);
        my $output;
        $status = $inflate->inflate($decrypted_data, $output);
        $decrypted_data = $output;
    }

    # Decode JSON to get original paste content
    my $paste_content = decode_json($decrypted_data);

    return $paste_content;
}


# Combine getting and decoding one step
sub get_and_decode {
    my ($self, $paste_id, $disable_ssl_verification) = @_;
    my $paste_data = $self->get_paste($paste_id, $disable_ssl_verification);
    my $password = $paste_id;
    $password =~ s/#-?(.*)$/$1/;
    return $self->decode_paste($paste_data, $password);
}

# Combine encoding and posting into one step
sub encode_and_post {
    my ($self, $disable_ssl_verification) = @_;
    my $raw_data = $self->encode_paste();
    return $self->post_paste($raw_data, $disable_ssl_verification);
}

1; # The module must return a true value
