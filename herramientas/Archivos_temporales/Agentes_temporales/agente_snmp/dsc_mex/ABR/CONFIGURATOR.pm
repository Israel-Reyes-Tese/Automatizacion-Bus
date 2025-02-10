package ABR::CONFIGURATOR;
# Version=6.0
use ABR::HashOrder;
use warnings;
use strict;
use Carp;
use Data::Dumper;


# Constructor
sub new {
    my ($class, %args) = @_;
    my $config_file = $args{config_file} or die "> [ERROR]: CONFIGURATOR.pm, Configurator: No configuration file provided\n";
    my %hash_read;
    return bless { config_file => $config_file, hash_read => \%hash_read }, $class;
}

# Main function to read the configuration file
sub read_config {
    my $self = shift;
    my $config_file = $self->{config_file};
    my $config_ref  = $self->{hash_read};
    my $hashOrdered = ABR::HashOrder->new();

    eval {
        open(my $fh, '<', $config_file) or croak "Error: Could not open the configuration file: $config_file";
        while (my $line = <$fh>) {
            chomp($line);
            next if $line =~ /^s*$/ or $line =~ /^#/;  # Skip empty lines and comments
            my ($index, $value) = parse_line($line);

            # Eliminar espacios en blanco al principio y al final
            $index =~ s/^s+|s+$//g;  # Trim leading and trailing whitespace
            $value =~ s/^s+|s+$//g;  # Trim leading and trailing whitespace
            # Eliminar saltos de línea
            $index =~ s/[\r\n]//g;
            $value =~ s/[\r\n]//g;

            $hashOrdered->set($index => $value);
        }
        close($fh);
        $config_ref->{"GLOBAL"} = $hashOrdered;
    };
    if ($@) {
        print STDERR "Error in read_config: $@\n";
        croak "Error in read_config: $@";
    }

    return $config_ref;
}

# Helper function to parse a line from the configuration file
sub parse_line {
    my ($line) = @_;
    my @splitted = split(":=", $line);
    $splitted[0] =~ s/^s+|s+$//g;  # Trim leading and trailing whitespace
    $splitted[1] =~ s/^s+|s+$//g;  # Trim leading and trailing whitespace
    return ($splitted[0], $splitted[1]);
}

# Function to read a map from the configuration file
sub read_map {
    my ($self, $tag, $sep, $config_file) = @_;
    my $hash_ref    = $self->{hash_read};
    my $hashOrdered = ABR::HashOrder->new();

    unless ($config_file) {
        print STDERR "> [ERROR]: CONFIGURATOR.pm, Verify configuration file: AGENT.properties\n";
        die "> [ERROR]: CONFIGURATOR.pm, Could not open the configuration file\n";
    }

    open(my $fh, '<', $config_file) or die "> [ERROR]: CONFIGURATOR.pm, Could not open the configuration file: $config_file\n";
    while (my $line = <$fh>) {
        chomp($line);
        next if $line =~ /^s*$/ or $line =~ /^#/;
        my @splitted = split($sep, $line);
        my $index = ifexists($splitted[0]) ? $splitted[0] =~ s/^s+|s+$//gr : '';
        my $value = ifexists($splitted[1]) ? $splitted[1] =~ s/^s+|s+$//gr : '';
        $hashOrdered->set($index => $value) if $index && $value;
    }
    close($fh);

    $hash_ref->{$tag} = $hashOrdered;
    return $hash_ref;
}

# Function to check if a variable exists and is not empty
sub ifexists {
    my $variable = shift;
    return defined $variable && $variable ne "";
}

1;
