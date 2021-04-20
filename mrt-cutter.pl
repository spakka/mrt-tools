#!/usr/bin/env perl
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later
# as published by the Free Software Foundation.
#
# This work is based on zebra-dump-parser.pl, by Marco d'Itri
# https://github.com/rfc1036/zebra-dump-parser
# please see this work for the original
# 
# This program is designed to chop up an MRT file into individual records
# to allow specific records to be more easily analysed, and subsequently
# used on their own as test cases.
#
# By default, when processing a TABLE_DUMP_V2 file, it will read the most
# recent PEER_INDEX_TABLE record and prepend it to all subsequent RIB entries
# so their peer indexes are available.
#
# USAGE:
# Pipe your uncompressed MRT file to this program on STDIN.
# It will create a file called {number}.mrt for each record in the input stream.
# To avoid exploding your filesystem limits, it will put each file into
# a TAR archive that will be written to 'mrt-records.tar.
# You can then use standard 'tar' tools to extract individual files from
# the archive.

use warnings;
use strict;
use Archive::Tar
require 5.008;

use constant {
	# Types of interest
        MSG_TABLE_DUMP_V2                       => 13,  # TABLE_DUMP_V2
	MSG_BGP4MP				=> 16,  # BGP4MP
	MSG_BGP4MP_ET				=> 17,  # BGP4MP_ET
	MSG_ISIS_ET				=> 33,	# ISIS_ET
	MSG_OSPFv3_ET				=> 49,  # OSPFv3_ET

	# Subtypes of interest
        # for TABLE_DUMP_V2
        PEER_INDEX_TABLE                        => 1,
        RIB_IPV4_UNICAST                        => 2,
        RIB_IPV4_MULTICAST                      => 3,
        RIB_IPV6_UNICAST                        => 4,
        RIB_IPV6_MULTICAST                      => 5,
        RIB_GENERIC                             => 6,

};

##############################################################################
open(INPUT, '<-') or die "Could not open INPUT $!\n";

#binmode(INPUT);
#binmode(OUTPUT);

use constant BUF_READ_SIZE => 4096 * 8;
my $buf = '';
my $read_done = 0;
my $record_index = 0;
my $index_table = '';

my $tar = Archive::Tar->new;

while (1) {
        if ($read_done) {
                last if length $buf == 0;
        } elsif (length $buf < BUF_READ_SIZE) {
                my $tmp = '';
                my $n = sysread(INPUT, $tmp, BUF_READ_SIZE * 2);
                die "sysread: $!" if not defined $n;
                $read_done = 1 if $n == 0;
                $buf .= $tmp;
        }

        die "short file (empty packet)" if not $buf;
        my $header = substr($buf, 0, 12, '');
        my ($time, $type, $subtype, $packet_length) = unpack('N n n N', $header);

	
	# If type is an ET type, read the extra timestamp
	my $ms_time = 0;
        my $ms_data = '';

	if (($type == MSG_BGP4MP_ET) || ($type == MSG_ISIS_ET) || ($type == MSG_OSPFv3_ET )) {
		$ms_data = substr($buf, 0, 4, '');
		$header .= $ms_data;
		($ms_time) = unpack('N', $ms_data);
		$packet_length -= 4;
	}
	
        my $packet = substr($buf, 0, $packet_length, '');
        die "short file (got " . (length $packet) . " of $packet_length bytes)"
                if $packet_length != length $packet;

        handle_mrt_packet(\$header, \$packet, $type, $subtype);
}
close(INPUT);
$tar->write('mrt-records.tar');
exit 0;

##############################################################################

sub handle_mrt_packet {

	my ($header, $packet, $type, $subtype) = @_;

	# We special-case MSG_TABLE_DUMP_V2 and grab and store the PEER_INDEX_TABLE.
	if ($type == MSG_TABLE_DUMP_V2) {
		if ($subtype == PEER_INDEX_TABLE) {
			$index_table = $$header . $$packet;
			$tar->add_data( "${record_index}.mrt", $index_table );
		}
		else {
			$tar->add_data( "${record_index}.mrt", $index_table . $$header . $$packet);
		}
	} else {
		$tar->add_data( "${record_index}.mrt", $$header . $$packet);
	}

	$record_index++;
}
