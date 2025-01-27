package ABR::CONFIGURATOR;
# Version=6.0
use ABR::HashOrder;

use warnings;
use strict;

sub new
{
my $class = shift;
my $args;
my $config_file;
my %hash_read;

    $args = {@_};

    for(keys(%{$args}))
    {
        if ($_ eq "config_file") {
            $config_file = $args -> {$_};
        } else {

          die "> [ERROR]: CONFIGURATOR.pm, Configurator: No configuration file provided\n";
        }
    }

    return bless { config_file => $config_file, hash_read => \%hash_read };
}

sub read_config
{
my $self        = shift;
my $config_file = $self -> {config_file};
my $config_ref  = $self -> {hash_read};
my $hashOrdered = ABR::HashOrder -> new();
my @splitted;

    open(FILEH, "<", $config_file) or die "> [ERROR]: CONFIGURATOR.pm, Could not open the configuration file: " . $config_file . "\n";

    while (my $line = <FILEH>)
    {
        chomp($line);

        if($line !~ /^\s*$/ and $line !~ /^#/)
        {
            @splitted = split(":=", $line);
            $splitted[0] =~ /[ \t]*(.+)[ \t]*/;
            my $index = $1;
            $splitted[1] =~ /[ \t]*(.+)[ \t]*/;
            my $value = $1;
            $hashOrdered -> set($index => $value);
            $config_ref -> {"GLOBAL"} = $hashOrdered;
        }
    }

    return $config_ref;
}


sub read_map
{
my $self        = shift;
my $tag         = shift;
my $sep         = shift;
my $config_file = shift;
my $hash_ref    = $self -> {hash_read};
my $hashOrdered = ABR::HashOrder -> new();
my @splitted;
    if(!($config_file)){
      print "> [ERROR]: CONFIGURATOR.pm, Verify configuration file: AGENT.properties\n";

      print "> [ERROR]: CONFIGURATOR.pm, Maybe some of the indexes used are not well written in your *.pl or AGENT.properties file\n";

      for my $k($hash_ref -> {"GLOBAL"} -> keys){
        print "> [ERROR]: CONFIGURATOR.pm, index -> $k\n";

      }


      die "> [ERROR]: CONFIGURATOR.pm, Could not open the configuration file\n";
    }
    open(FILEH, "<", $config_file) or die "> [ERROR]: CONFIGURATOR.pm, Could not open the configuration file: " . $config_file . "\n";

    while (my $line = <FILEH>)
    {
        chomp($line);

        if($line !~ /^\s*$/ and $line !~ /^#/)
        {
            @splitted = split($sep, $line);
            my $index = "";
            my $value = "";
            if(ifexists($splitted[0])){
              $splitted[0] =~ /[ \t]*(.+)[ \t]*/;
              $index = $1;
            }
            if(ifexists($splitted[1])){
              $splitted[1] =~ /[ \t]*(.+)[ \t]*/;
              $value = $1;
              $hashOrdered -> set($index => $value);
              $hash_ref -> {$tag} = $hashOrdered;
            }
        }
    }
    return $hash_ref;
}

sub ifexists
{
 my $variable = shift;
 if (defined $variable && $variable ne ""){
   return 1;
 } else {
   return 0;
 }
}


1;
