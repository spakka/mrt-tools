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
# It has been heavily modified by Colin Petrie (@ RIPE NCC)
# to perform the task of re-writing incorrectly-coded attributes
# in MRT RIB TABLE_DUMP_V2 files produced by Quagga v1.2.0 and higher
# caused by a bug in Quaggas Large Communities implementation
#
# It attempts to re-write a second occurrence of the COMMUNITIES (8) attribute 
# code to be LARGE COMMUNITIES (32), within RIB entries
#
# DATA WARNING:
#
# This code *cannot* compensate for RIB entries that have did not have regular COMMUNITIES.
# This code only fixes attributes with mis-tagged LARGE COMMUNITIES, in *addition* to 
# regular COMMUNITIES - it looks for a *second* occurrence of the COMMUNITIES(8) attribute,
# and changes it to LARGE COMMUNITES(32)
#
# If there is only one COMMUNITIES(8) attribute, it is not possible to determine 
# whether a fixup is necessary or not.
# 
# USAGE:
# pipe your uncompressed RIB file to this program on STDIN
# your repaired data comes out of STDOUT, pipe this to your new file
# any logging is with warn or die, and should appear on STDERR

use warnings;
use strict;
require 5.008;

# set verbose to 1 to log many things.
# try not to conflict it with $quiet (below)
my $verbose=0;

# set quiet to 0 to only log fixups and conversion summary
# set quiet to 1 to only log conversion summary
# set quiet to >1 to log nothing except die()s
my $quiet=1;

use constant {
        MSG_TABLE_DUMP_V2                       => 13,  # TABLE_DUMP_V2

        # for TABLE_DUMP_V2
        PEER_INDEX_TABLE                                => 1,
        RIB_IPV4_UNICAST                        => 2,
        RIB_IPV4_MULTICAST                      => 3,
        RIB_IPV6_UNICAST                        => 4,
        RIB_IPV6_MULTICAST                      => 5,
        RIB_GENERIC                                     => 6,

	# BGP attributes of interest
        BGP_ATTR_COMMUNITIES            => 8,
        BGP_ATTR_LARGE_COMMUNITIES        => 32,

	# BGP flag of interest
        BGP_ATTR_FLAG_EXTLEN            => 0x10,

};

##############################################################################
open(INPUT, '<-') or die "Could not open INPUT $!\n";
open(OUTPUT, '>-') or die "Could not open OUTPUT $!\n";

#binmode(INPUT);
#binmode(OUTPUT);

use constant BUF_READ_SIZE => 4096 * 8;
my $buf = '';
my $read_done = 0;

# Track total number of fixups performed
my $fixups_performed = 0;

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
        my $packet = substr($buf, 0, $packet_length, '');
        die "short file (got " . (length $packet) . " of $packet_length bytes)"
                if $packet_length != length $packet;


	syswrite(OUTPUT, $header);
        decode_mrt_packet(\$packet, $type, $subtype);
}
print STDERR "Completed - total number of fixups performed: $fixups_performed\n" if $quiet <= 1;
close(INPUT);
close(OUTPUT);
exit 0;

##############################################################################

sub decode_mrt_packet {

	my ($pkt, $type, $subtype) = @_;
	if ($type != MSG_TABLE_DUMP_V2) {
		warn("not a TABLE_DUMP_V2 record - passing through - you are probably not running this program against a TABLE_DUMP_V2 file") unless $quiet;
		syswrite(OUTPUT, $$pkt);
	} else {
		warn("processing TABLE_DUMP_V2 record") if $verbose;

		if ($subtype == PEER_INDEX_TABLE) {
			warn("- peer index table found, passing through") if $verbose;
			syswrite(OUTPUT, $$pkt);
			return;
		} elsif ($subtype == RIB_IPV4_UNICAST) {
		} elsif ($subtype == RIB_IPV4_MULTICAST) {
		} elsif ($subtype == RIB_IPV6_UNICAST) {
		} elsif ($subtype == RIB_IPV6_MULTICAST) {
		} else {
			warn("- unknown TABLE_DUMP_V2 subtype, passing through - don't know how to handle/fixup") unless $quiet;
			syswrite(OUTPUT, $$pkt);
			return;
		}

		# read how many bytes to consume from NLRI (+seq)
		my ($seq_num, $prefixlen, $tmp) = unpack('N C a*', $$pkt);
		my $bytes = int($prefixlen / 8) + ($prefixlen % 8 ? 1 : 0);

		# consume and pass through correct amount (seq(4), prefixlen(1), entrycount(2), prefix(variable))
		my $rib_entry_header = substr($$pkt, 0, 7+$bytes, '');
		warn("- processing one prefix") if $verbose;
		syswrite(OUTPUT, $rib_entry_header);

		# Now we iterate over RIB Entries (variable)
		while (length $$pkt > 0) {

			my $num_communities_found = 0;

			# consume and pass through RIB Entry header
			# peer index (2), originated time (4), attribute length (2)
			my ($peer_index, $originated, $attribute_length, $tmp2) = unpack('n N n a*', $$pkt);
			my $attr_header = substr($$pkt, 0, 8, '');
			warn("-- processing one RIB entry for prefix") if $verbose;
			syswrite(OUTPUT, $attr_header);

			my $attr = substr($$pkt, 0, $attribute_length, '');
			warn("--- processing attr blob in RIB entry") if $verbose;
			#syswrite(OUTPUT, $attr);


			# Process the attributes
			while (length $attr > 0) {

				my ($flags, $type, $attr_tmp) = unpack('C C a*', $attr);
				my $this_attr;
				my $this_attr_header;
				my $this_attr_length;

				if ($flags & BGP_ATTR_FLAG_EXTLEN) {
					($flags, $type, $this_attr_length, $attr_tmp) = unpack('C C n a*', $attr);
					$this_attr_header = substr($attr, 0, 4, '');
				} else {
					($flags, $type, $this_attr_length, $attr_tmp) = unpack('C C C a*', $attr);
					$this_attr_header = substr($attr, 0, 3, '');
				}
				warn ("---- processing attr, flag: $flags, type: $type, length: $this_attr_length") if $verbose;

				$this_attr = substr($attr, 0, $this_attr_length, '');

				if ($type != BGP_ATTR_COMMUNITIES) {
					# Consume and pass through if not COMMMUNITIES
					syswrite(OUTPUT, $this_attr_header);
					syswrite(OUTPUT, $this_attr);

				} else {

					# Now for the real fun!!
					# This part, is the reason this code exists :)
					$num_communities_found++;
					if ($num_communities_found == 1) {
						# Consume and pass through first COMMUNITES blob - legitimate
						warn ("----- passing through first (legitimate) COMMUNITIES attribute") if $verbose;
						syswrite(OUTPUT, $this_attr_header);
						syswrite(OUTPUT, $this_attr);

					} elsif ($num_communities_found == 2) {
						# Fix up type code to LARGE COMMUNITES, then pass through
						warn ("----- fixing up second (bad) COMMUNITIES to LARGE COMMUNITIES attribute") if $verbose;
						warn ("-- fixing up second (bad) COMMUNITIES to LARGE COMMUNITIES attribute") unless $quiet;
						$fixups_performed++;

						if ($flags & BGP_ATTR_FLAG_EXTLEN) {
							$this_attr_header = pack ('C C n', $flags, BGP_ATTR_LARGE_COMMUNITIES, $this_attr_length);
						} else {
							$this_attr_header = pack ('C C C', $flags, BGP_ATTR_LARGE_COMMUNITIES, $this_attr_length);
						}
						syswrite(OUTPUT, $this_attr_header);
						syswrite(OUTPUT, $this_attr);

					} else {
						die ("------ found more COMMUNITIES than 2 - outside remit of this program, don't know how to handle!\nInvestigate this MRT file!");
					};
				}
			}
		}
	}
}

