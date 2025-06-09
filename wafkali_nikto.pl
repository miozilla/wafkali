#!/usr/bin/perl

# chmod +x wafkali_nikto.pl
# ./wafkali_nikto.pl

use strict;
use warnings;
use XML::Simple;
use Data::Dumper;

# --- Configuration ---
my $target = "http://example.com";  # <-- Change this to your target
my $xml_output = "nikto_output.xml";

# --- Nikto Command (XML format) ---
my $nikto_cmd = "nikto -h $target -output $xml_output -Format xml";

print "[*] Running Nikto scan on $target...\n";

# --- Run the command ---
my $exit_code = system($nikto_cmd);

# --- Check if scan was successful ---
if ($exit_code != 0) {
    die "[-] Nikto scan failed with exit code $exit_code\n";
}

print "[+] Scan complete. Parsing results from $xml_output...\n";

# --- Parse XML output ---
my $xml_data = eval { XMLin($xml_output, ForceArray => ['item']) };
if ($@) {
    die "[-] Failed to parse XML: $@\n";
}

# --- Extract & Print Vulnerabilities ---
my $items = $xml_data->{niktoscan}->{scandetails}->{item};

if ($items && @$items) {
    print "[!] Issues found:\n";
    foreach my $item (@$items) {
        print "---------------------------\n";
        print "OSVDB: $item->{osvdb}\n" if $item->{osvdb};
        print "Description: $item->{description}\n";
        print "URI: $item->{uri}\n";
    }
} else {
    print "[+] No issues found or no 'item' nodes in XML.\n";
}
