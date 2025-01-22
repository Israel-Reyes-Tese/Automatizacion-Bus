package ABR::FILE_HANDLER;
# Version=1.0
use warnings;
use strict;

sub new {
    my $class = shift;
    my $self = {};
    bless $self, $class;
    return $self;
}

sub read_file {
    my ($self, $file_path) = MainWindow=HASH(0x19ca5c3d4f0) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    open my $fh, '<', $file_path or die "No se puede abrir el archivo: $!";
    my @lines = <GLOB(0x19ca5d61270)>;
    close $fh;
    return @lines;
}

sub write_file {
    my ($self, $file_path, @lines) = MainWindow=HASH(0x19ca5c3d4f0) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    open my $fh, '>', $file_path or die "No se puede abrir el archivo: $!";
    print $fh @lines;
    close $fh;
}

1;
