#!/usr/bin/perl

=head1 NAME

dbus-introspect.pl - List the services available in D-Bus.

=head1 DESCRIPTION

This program list the methods available in a D-Bus object. It uses the
introspection mechanism defined in D-Bus for listing all methods.

For more details see L<http://dbus.freedesktop.org/doc/dbus-specification.html#standard-interfaces-introspectable>.

=head1 SYNOPSIS

dbus-introspect.pl [OPTION] service object

Where I<service> is a D-Bus service such as C<org.freedesktop.DBus> and 
I<object> is an object available in the bus such as 
C</org/freedesktop/DBus>.

Options: 

  --system   use the system bus.
  --session  use the session bus.

=head1 AUTHOR

Emmanuel Rodriguez E<lt>potyl@cpan.orgE<gt>

=head1 COPYRIGHT

Copyright 2008 by Emmanuel Rodriguez

=cut


use strict;
use warnings;

use Net::DBus;
use XML::LibXML;
use Data::Dumper;
use Getopt::Long qw(:config auto_help pass_through);

exit main();

sub main {
	
	my $use_session = 1;
	GetOptions(
		'system'  => sub {$use_session = 0},
		'session' => sub {$use_session = 1},
	);
	my ($service_name, $object_name) = @ARGV;
	$service_name ||= 'org.freedesktop.DBus';
	$object_name ||= '/org/freedesktop/DBus';


	
	# Get the introspection object
	my $bus = $use_session ? Net::DBus->session : Net::DBus->system;
	my $introspection = $bus->get_service($service_name)->get_object($object_name);
	
	# Get the list of methods offered by the DBus service
	my $xml = $introspection->Introspect();
	display_results($xml);

	return 0;
}


sub display_results {
	my ($xml) = @_;
	
#	print $xml;

	# Do not validate the document against the DTD, the download is painful
	my $parser = XML::LibXML->new();
	$parser->load_ext_dtd(0);
	my $doc = $parser->parse_string($xml);
	
	# Dump each interface
	foreach my $node_interface ($doc->findnodes('/node/interface')) {
		my $interface = $node_interface->getAttribute('name');
		print "$interface\n";
		
		# Dump each method in the interface
		foreach my $node_method ($node_interface->findnodes('method')) {
			my $method = $node_method->getAttribute('name');
			
			# Prepare the arguments and return type of the interface
			my @return = ();
			my @args = ();
			foreach my $node_arg ($node_method->findnodes('arg')) {
				my $type = $node_arg->getAttribute('type');
				my $direction = $node_arg->getAttribute('direction') || 'in';
				if ('out' eq $direction) {
					push @return, $type;
				}
				else {
					push @args, $type;
				}
			}
			
			my $return = @return ? (join(', ', @return) ) : 'void';
			
			printf "\t%-4s $method(%s)\n",
				$return,
				join(', ', @args),
			;
		}
	}
	
}
