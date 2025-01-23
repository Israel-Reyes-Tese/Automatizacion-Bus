package ABR::HashOrder;
# Version=1.0
use warnings;
use strict;


sub ifexists
{
 my $variable = shift;
 if (defined $variable && $variable ne ""){
   return 1;
 } else {
   return 0;
 }
}

# Constructor
sub new {
  my $class = shift;
  my $args  = {@_};
  my $self;
  my %hash;
  my @array;

  my $type = "$args";
  if(ifexists($type)){
    if($type =~ /HASH/i){
      foreach my $x(keys %{$args}){
        # print "args: " . $x . " -> " . $args -> {$x} . "\n";
        # agregando al final del arreglo un elemento
        push(@array,$x);
        $hash{$x} = $args -> {$x};
      }
    }
  }

  $self = {hash_ref => \%hash, array_ref => \@array};
  return bless $self,$class;
}


sub exists{
  my $self = shift;
  my $key  = shift;
  if(ifexists($key)){
    if(ifexists($self -> {hash_ref}{$key})){
      return 1;
    }else{
      return 0;
    }
  }else{
    return 0;
  }
}


sub delete{
  my $self     = shift;
  my $key      = shift;
  my $size_arr = 0;

  if(ifexists($key)){
    if(ifexists($self -> {hash_ref}{$key})){
      # Eliminando la llave del hash_ref
      delete $self -> {hash_ref}{$key};

      # Eliminando la llave del array_ref
      $size_arr = @{$self -> {array_ref}};
      if($size_arr != 0){
        for (my $var = 0; $var < $size_arr; $var++) {
          # print "index: " . $var . " -> " . $self -> {array_ref}[$var] . "\n";
          if($self -> {array_ref}[$var] eq $key ){
            splice(@{$self -> {array_ref}},$var,1);
            last;
          }
        }
      }

    }
  }

}

sub get{
  my $self     = shift;
  my $key      = shift;

  if(ifexists($key)){
    if(ifexists($self -> {hash_ref}{$key})){
      return $self -> {hash_ref}{$key};
    }else{
      return "";
    }
  }else{
    return "";
  }
}


sub set{
  my $self     = shift;
  my $input1   = shift;
  my $input2   = shift;
  my $size_arr = 0;

  if(ifexists($input1)){
    if(ifexists($input2)){
      push(@{$self -> {array_ref}},$input1);
      $self -> {hash_ref}{$input1} = $input2;
    }
  }

}

sub keys{
  my $self   = shift;
  my $size   = 0;

  $size = @{$self -> {array_ref}};
  if($size != 0){
    return $self -> {array_ref};
  }

  return "";
}


sub getSize{
  my $self   = shift;
  my $size   = 0;
  $size = @{$self -> {array_ref}};
  return $size;
}

1;
