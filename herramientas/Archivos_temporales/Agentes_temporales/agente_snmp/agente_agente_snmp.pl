#!/usr/bin/perl -I .

use strict;
use warnings;

use ABR::HashOrder;
use FindBin;
use lib $FindBin::Bin;

use ABR::SNMPAgente;
use ABR::FILE_HANDLER;
use ABR::MICROTIME;
use ABR::Parser_aux;
use ABR::CONFIGURATOR;
use ABR::TapFilter;

my $conf_file    = $FindBin::Bin . "/AGENT.properties";
my $configurator = ABR::CONFIGURATOR -> new(config_file => $conf_file);
my $hashOrdered  = ABR::HashOrder -> new();
my $hash_ref     = $configurator -> read_config();
my $maps         = "";
my $bFilters     = "";
my $cFilters     = "";
my $ndate        = "";
my $file_name    = "";
my $warning      = "";
my $timeUpdate   = "";
my $minutos      = 0;
my $abstract_global_hash;
my $message;
my $trap_ref;
my $rtrn;

open my $fh, '>', $FindBin::Bin . "/output.log" or die "Could not open file: $!";
$fh->autoflush(1);

FuncInfo(\@ARGV,$FindBin::Bin);

for (keys(%{$hash_ref})){
  $hashOrdered = $$hash_ref{$_};
  for my $key (@{$hashOrdered -> keys}){
    my $value = $hashOrdered -> get($key);
    if ($value =~ /CONF\/MAP.+/) {
      if(FileExists($FindBin::Bin . "/" . $value) && FileIsEmpty($FindBin::Bin . "/" . $value)){
        $hash_ref = $configurator -> read_map("$key",'\s*->\s*',$FindBin::Bin . "/" . $hashOrdered -> get("$key"));
        if(ifexists($hash_ref -> {$key})){
          $maps .= "$key,";
          $abstract_global_hash .= "\n > MAPA EXTERNO \t'$key'";
          for (@{$$hash_ref{$key} -> keys}){
            print $fh "\n   > KEY: '$_'    VALUE:    '" . $$hash_ref{$key} -> get($_) . "'";
          }
        } else {
          $warning .= "\nThe file '$FindBin::Bin/$value' with key '$key' is empty and generate an empty hash. The key '$key' will be removed from the hash";
          delete $hash_ref -> {$key};
        }
      }
    } elsif ($value =~ /CONF\/FB.+/) {
      if(FileExists($FindBin::Bin . "/" . $value) && FileIsEmpty($FindBin::Bin . "/" . $value)){
        $hash_ref = $configurator -> read_map("$key",'\s*->\s*',$FindBin::Bin . "/" . $hashOrdered -> get("$key"));
        if(ifexists($hash_ref -> {$key})){
          $bFilters .= "$key,";
          $abstract_global_hash .= "\n > FILTRO DE BLOQUEO \t'$key'";
          for (@{$$hash_ref{$key} -> keys}){
            print $fh "\n   > KEY: '$_'    VALUE:    '" . $$hash_ref{$key} -> get($_) . "'";
          }
        } else {
          $warning .= "\nThe file '$FindBin::Bin/$value' with key '$key' is empty and generate an empty hash. The key '$key' will be removed from the hash";
          delete $hash_ref -> {$key};
        }
      }
    } elsif ($value =~ /CONF\/FC.+/) {
      if(FileExists($FindBin::Bin . "/" . $value) && FileIsEmpty($FindBin::Bin . "/" . $value)){
        $hash_ref = $configurator -> read_map("$key",'\s*->\s*',$FindBin::Bin . "/" . $hashOrdered -> get("$key"));
        if(ifexists($hash_ref -> {$key})){
          $cFilters .= "$key,";
          $abstract_global_hash .= "\n > FILTRO CORRECTIVO \t'$key'";
          for (@{$$hash_ref{$key} -> keys}){
            print $fh "\n   > KEY: '$_'    VALUE:    '" . $$hash_ref{$key} -> get($_) . "'";
          }
        } else {
          $warning .= "\nThe file '$FindBin::Bin/$value' with key '$key' is empty and generate an empty hash. The key '$key' will be removed from the hash";
          delete $hash_ref -> {$key};
        }
      }
    } else {
      $abstract_global_hash .= "\n > VALOR DE $key:  '$value'";
    }
  }
  chop($bFilters);
  chop($cFilters);
  chop($maps);
}

#print $fh "########################## RESUMEN DE DATOS DEL AGENTE ########################## \n";
#print $fh "\n\nNOMBRE DEL AGENTE: ". $hashOrdered -> get('agt') ."\n";

my $host = $hashOrdered -> get('host');
my $port = $hashOrdered -> get('port');
my $glustDir = "/mnt/umplogic/" . $hashOrdered -> get('agt');
my $auxDir =  "/mnt/umpemergency/" . $hashOrdered -> get('agt');

my $trapd = ABR::SNMPAgente->new(
  $host, $port
);
my $fhandler = ABR::FILE_HANDLER->new(
  gluster_dir =>   $glustDir,
  auxiliary_dir => $auxDir
);

print $fh "EL DIRECTORIO GLUSTER ESTA EN: $glustDir\n";
print $fh "EL DIRECTORIO AUXILIARY ESTA EN: $auxDir\n";

if(ifexists($maps))    { print $fh "LOS EXTERNAL MAPS SON: $maps\n";}
if(ifexists($bFilters)){ print $fh "LOS BLOCKING FILTERS SON: $bFilters\n";}
if(ifexists($cFilters)){ print $fh "LOS CORRECTIVE FILTERS SON: $cFilters\n";}
print $fh "El GLOBAL HASH es: $abstract_global_hash\n";
if(ifexists($warning)){
  my @s = split('\n',$warning);
  foreach(@s){
    if(ifexists($_)){
      print $fh "> \[WARNING\]: " . $_ . "\n";
    }
  }
}
##################################### Tap Filters #####################################

print $fh "LOS FILTROS DE BLOQUEO SON: $bFilters\n";
print $fh "LOS FILTROS CORRECTIVOS SON: $cFilters\n";
my $filter = ABR::TapFilter -> new(
  hash_ref      => \%$hash_ref,
  config_index  => "$bFilters",
  split_filter1 => '\<&&\>' ,
  split_filter2 => '\<\>'
);
my $parser = ABR::Parser_aux->new();

$fhandler->startup_write();

while (1) {
  $trap_ref = $trapd->get_trap($hashOrdered -> get('ALARM_PRINTS'));
  if ($trap_ref) {
    $message = $parser -> formatter($trap_ref,$hash_ref,$hashOrdered -> get('ALARM_PRINTS'));
    if ( defined($message) ) {
      $ndate = ABR::MICROTIME::getmicro();
      $file_name = $hashOrdered -> get('agt') . "." . $ndate . "." . "yes";
      $file_name = $filter -> ProcessingFilters($message, $file_name);
      $filter -> PrintFilterConditionFulfilled();
      $rtrn = $fhandler->write_file( $file_name, $message );
    } else {
      if($hashOrdered -> get('ALARM_PRINTS')){print $fh "\nFile not created\n\n  ";}
    }
  } else {
    $fhandler->dummy_write();
  }
}


  close $fh or warn "Advertencia: No se pudo cerrar el archivo log: $!";


sub FileExists{
  my $file = shift;
  if(-e $file){
    return 1;
  } else {
    $warning .= "\nThe file '$file' not found.";
    return 0;
  }
}

sub FileIsEmpty{
  my $file = shift;
  if(-s $file == 0){
    $warning .= "\nThe file '$file' is empty.";
    return 0;
  } else {
    return 1;
  }
}

sub ifexists{
  my $variable = shift;
  if (defined $variable && $variable ne ""){
    return 1;
  } else {
    return 0;
  }
}

sub FuncInfo{
  my $input   = shift;
  my $path    = shift;
  my @files   = ("TapFilter.pm","CorrectiveFilter.pm","HashOrder.pm","SNMPAgente.pm","Parser_aux.pm","MICROTIME.pm","LogsFile.pm","llenaComun.pm","FILE_HANDLER.pm");
  my $command = "";
  foreach(@{$input}){
    if(ifexists($_)){
      if($_ =~ /--version/){
        foreach my $f(@files){
          if(FileExists("$path/ABR/$f")){
            $command = `cat $path/ABR/$f | grep 'Version='`;
            chop($command);
            if(ifexists($command)){if($command =~ /#\s*(Version=.*)/i){print $fh "   -$f -> " . $1 . "\n";}}
            else{print $fh "   -$f -> \"is not define version\"\n";}
          }
        }
        die;
      } elsif($_ =~ /--help/){
        print $fh "\nValid options:\n";
        print $fh " --help   " . "." . $path . "/" . $0 . " [--help]\n";
        print $fh " --version   " . "." . $path . "/" . $0 . " [--version]\n";
        die;
      } else {
        print $fh "\nInvalid option: " . $_ . "\n";
        print $fh "\nValid options:\n";
        print $fh " --help   " . "." . $path . "/" . $0 . " [--help]\n";
        print $fh " --version   " . "." . $path . "/" . $0 . " [--version]\n";
        die;
      }
    }
  }
}
