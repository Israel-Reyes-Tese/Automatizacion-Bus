package LogicEstructura;

use strict;
use warnings;

use Tk;
use TK::Table;

# Añadir la carpeta donde se encuentran los modulos
use lib $FindBin::Bin . "/herramientas";
use lib $FindBin::Bin . "./Script Generacion de Agentes SNMP/utilidades";


use SNMP::MIB::Compiler;

# Ventanas secundarias
use MIB_utils;

use Data::Dumper; # Importar el modulo Data::Dumper

use File::Path qw(make_path rmtree);
use File::Temp qw(tempfile);

use File::Spec;
use File::Basename;

use Cwd 'abs_path';

use FindBin;

use Data::Dumper;
use Toolbar;
use Estilos;
use Complementos;
use Rutas;



# Placeholder functions for card commands
sub crear_codigo_principal {
    # ...implementation...
}

sub crear_codigo_parseador {
    # ...implementation...
}

sub crear_archivo_subrutinas {
    my ($ventana_principal, $agente, $ruta_agente, $alarmas_principales, $alarmas_secundarias) = @_;
    $agente ||= 'agente_snmp';
    print "Nombre del agente: $agente\n";
    print "Ruta del agente: $ruta_agente\n";
    
    my $ruta_agente_completa = File::Spec->catfile($ruta_agente, $agente);
    # Validar si el nombre del agente se repite en la ruta completa
    if ($ruta_agente_completa =~ /$agente.*$agente/) {
        $ruta_agente_completa =~ s/\\$agente//;
    }
    print "Ruta del agente completa: $ruta_agente_completa\n";

    unless (-d $ruta_agente_completa) {
        my $entry_ruta_agente = herramientas::Complementos::register_directory($ventana_principal, 'Selecciona la ruta donde se creara el agente', "Buscar");
        $ruta_agente_completa = File::Spec->catfile($entry_ruta_agente, $agente);
        unless (-d $ruta_agente_completa) {
             herramientas::Complementos::show_alert($ventana_principal, 'ERROR', 'La ruta del agente no existe', 'error');
            return;
        }
    }
    
    my $archivo_agente = File::Spec->catfile($ruta_agente_completa, 'ABR', "$agente.pm");
    
    if (-e $archivo_agente) {
        open my $fh, '>', $archivo_agente or die "No se puede abrir el archivo: $!";
        close $fh;
    }
    
    open my $fh, '>>', $archivo_agente or die "No se puede abrir el archivo: $!";
    
    print $fh <<"END_CODE";
package ABR::$agente;

use warnings;
use strict;
use Digest::MurmurHash qw(murmur_hash);
use ABR::llenaComun;
my \$llena = ABR::llenaComun->new();
use ABR::CorrectiveFilter;
my \$cf = ABR::CorrectiveFilter->new(split_filter1 => '\\<&&\\>', split_filter2 => '\\<\\>');

my \$dat_MO;

sub ifexists {
    my \$variable = shift;
    return defined \$variable && \$variable ne "";
}

sub ifExistsAndNumber {
    my \$variable = shift;
    return defined \$variable && \$variable ne "" && \$variable =~ /^[-+]?[0-9]*\\.?[0-9]+\$/;
}

sub HostRegex {
    my (\$configHost_ref, \$ip_address) = \@_;
    my \$salida = "";
    if (ifexists(\$configHost_ref)) {
        foreach my \$k (\$configHost_ref->keys) {
            if (\$ip_address =~ /\\\$k/) {
                \$salida = \$configHost_ref->get(\$k);
            }
        }
    }
    return \$salida;
}

sub get_managed_object {
    my (\$hostname, \$agent_address, \$dat_managed_object) = \@_;
    my \$dat_MO = "";
    if (ifexists(\$hostname)) {
        if (ifexists(\$dat_managed_object)) {
            \$dat_MO = \$hostname . " " . \$dat_managed_object;
        } else {
            \$dat_MO = \$hostname;
        }
    } elsif (ifexists(\$dat_managed_object)) {
        \$dat_MO = "HostND " . \$agent_address . " " . \$dat_managed_object;
    } else {
        \$dat_MO = "HostND " . \$agent_address;
    }
    if (ifexists(\$dat_MO)) {
        \$dat_MO =~ s/"//g;
        \$dat_MO = "\\" . \$dat_MO . "\\"";
    }
    return \$dat_MO;
}

sub FuncAdditionalInfo {
    my (\$entrada, \$tp_name) = \@_;
    my \$add_info = " | AddInfo: trap name=" . \$tp_name . ", ";
    foreach my \$k (keys %\$entrada) {
        unless (\$k =~ /^(IPADDR|EOID|SPEC_TRAP|GEN_TRAP|1.3.6.1.2.1.1.3|1.3.6.1.6.3.1.1.4.1)\$/) {
            if (ifexists(\$entrada->{\$k})) {
                \$add_info .= " " . \$k . ": " . \$entrada->{\$k} . ";";
            }
        }
    }
    return \$add_info;
}

sub CorrectiveFilter {
    my (\$hashAlarm_ref, \$config_ref, \$action, \$var, \$c) = \@_;
    my \$output = \$cf->ProcessingCF(\$hashAlarm_ref, \$config_ref, \$action, \$c);
    if (ifexists(\$output)) {
        return \$output;
    } elsif (\$var =~ "MO") {
        return \$hashAlarm_ref->{"MO"};
    } elsif (\$var =~ "AddTxt") {
        return \$hashAlarm_ref->{"AddTxt"};
    } elsif (\$var =~ "PS") {
        return \$hashAlarm_ref->{"PS"};
    }
}

sub trapSeverity {
    my \$vSeverity = shift;
    my \$severity = "";
    if (\$vSeverity eq "5") { \$severity = "Clear"; }
    if (\$vSeverity eq "4") { \$severity = "Critical"; }
    if (\$vSeverity eq "3") { \$severity = "Major"; }
    if (\$vSeverity eq "1") { \$severity = "Warning"; }
    if (\$vSeverity eq "0") { \$severity = "Clear"; }
    if (\$vSeverity eq "2") { \$severity = "Minor"; }
    if (\$vSeverity eq "6") { \$severity = "0"; }
    return \$severity;
}

END_CODE

    # Add subroutines for each alarm in alarmas_principales
    foreach my $alarm_name (keys %$alarmas_principales) {
        my $oid = $alarmas_principales->{$alarm_name}->{OID};
        $oid =~ s/\./_/g;  # Replace dots with underscores for subroutine name
        
        print $fh <<"END_SUB";
# $alarm_name
sub _$oid {
    my \$entrada = shift;
    my \$trap_name = shift;
    my \$config_ref = shift;
    my %config = %\$config_ref;
    my \$alarm_txt;
    my \$dat_specific_problem = "";
    my \$dat_severity = 0;
    my \$dat_probable_cause = 0;
    my \$dat_event_type = 10;
    my \$dat_managed_object;
    my \$dat_additional_text;
    my \$dat_event_time = \$llena->fecha();
    my \$dat_notification_id = "";
    my \$dat_correlated_notification_id = "";
    my \$agent_address = \$entrada->{"IPADDR"};
    my \$hostname = HostRegex(\$config{"HOST"}, \$agent_address);
    ################################################################################### 
    
    #---------- Personalizacion del trap 
    
    ################################################################################### 
}

END_SUB
    }

    close $fh;
}

sub crear_archivos_genericos {
    # ...implementation...
}


1;
