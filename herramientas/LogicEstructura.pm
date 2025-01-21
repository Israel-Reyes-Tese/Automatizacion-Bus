package LogicEstructura;

use strict;
use warnings;

use Tk;
use Tk::FileDialog;
use Tk::TableMatrix;
use Tk::Pane;

use FindBin;  # Añadir FindBin para obtener la ruta del script
use Data::Dumper; # Importar el modulo Data::Dumper

use File::Path qw(make_path rmtree);
use File::Temp qw(tempfile);

use File::Spec;
use File::Basename;

use Cwd 'abs_path';

# Añadir la carpeta donde se encuentran los modulos
use lib $FindBin::Bin . "/herramientas";
use lib $FindBin::Bin . "./Script Generacion de Agentes SNMP/utilidades";

# Ventanas secundarias
use MIB_utils;

use Toolbar;
use Estilos;
use Complementos;
use Rutas;

use SNMP::MIB::Compiler;



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

    my $ruta_agente_completa = File::Spec->catfile($ruta_agente, $agente);
    # Validar si el nombre del agente se repite en la ruta completa
    if ($ruta_agente_completa =~ /$agente.*$agente/) {
        $ruta_agente_completa =~ s/\\$agente//;
    }

    unless (-d $ruta_agente_completa) {
        my $entry_ruta_agente = herramientas::Complementos::register_directory($ventana_principal, 'Selecciona la ruta donde se creara el agente', "Buscar");
        $ruta_agente_completa = File::Spec->catfile($entry_ruta_agente, $agente);
        unless (-d $ruta_agente_completa) {
             herramientas::Complementos::show_alert($ventana_principal, 'ERROR', 'La ruta del agente no existe', 'error');
            return;
        }
    }
    
    my %lista_opciones_checkbox = (
        opciones => {
        'Agregar (description) Adiccional Text'          => 0, 
        'Agregar (TrapName)  Adiccional Text'            => 0,   
        'Asignar Severidad (description)'                => 0,
        
        }
    );

    my %lista_opciones_entry = (
        opciones => {
            'Esteblecer Severidad'                => 2,
            'Establecer Probable Cause'           => 0,
            'Establecer Event Type'               => 10,
            'Establecer Specific Problem'         => 0,
            'Establecer Notification ID (sucesivo)' => 1300,
        }
    );

    my %lista_opciones_combo_box = (
        opciones => {
            'Establecer Additional Text'  => ['Vacio', 'Descripcion', 'Descripcion + TrapName'],
            'Establecer Managed Object'   => ['Vacio', 'Host + Agent address + MO', 'Entrada generica'],
        }
    );

    my $data_extra = herramientas::Complementos::create_scrollable_panel_with_checkboxes_and_entries($ventana_principal, "Opciones de estructura",  \%lista_opciones_checkbox, \%lista_opciones_entry, \%lista_opciones_combo_box);

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

    my $notification_id = $data_extra->{entries}->{'Establecer Notification ID (sucesivo)'} || 1300;

    foreach my $alarm_name (keys %$alarmas_principales) {
        my $oid = $alarmas_principales->{$alarm_name}->{OID};
        my $description = $alarmas_principales->{$alarm_name}->{DESCRIPTION};
        $oid =~ s/\./_/g;  # Replace dots with underscores for subroutine name
        
        my $var_ps = $data_extra->{entries}->{'Esteblecer Severidad'};
        my $var_sp = $data_extra->{entries}->{'Establecer Specific Problem'};
        my $var_pc = $data_extra->{entries}->{'Establecer Probable Cause'};
        my $var_EventType = $data_extra->{entries}->{'Establecer Event Type'};
        
        my $addTxt = '';
        if ($data_extra->{combo_boxes}->{'Establecer Additional Text'} eq 'Descripcion') {
            $addTxt = $description . ",\n";
        } elsif ($data_extra->{combo_boxes}->{'Establecer Additional Text'} eq 'Descripcion + TrapName') {
            $addTxt = $description . "\\nTrapName = " . $alarm_name . ",\\n";
        }
        
        my $mo = '';
        if ($data_extra->{combo_boxes}->{'Establecer Managed Object'} eq 'Host + Agent address + MO') {
            $mo = "get_managed_object(\$hostname, \$agent_address, \$mo)";
        } elsif ($data_extra->{combo_boxes}->{'Establecer Managed Object'} eq 'Entrada generica') {
            $mo = '\$entrada->{"1.3.6.1.6.3.18.1.3"}';
        }

        print $fh <<"END_SUB";
# $alarm_name
sub _$oid {
    my \$entrada = shift;
    my \$trap_name = shift;
    my \$config_ref = shift;
    my %config = %\$config_ref;

    my \$alarm_txt;

    my \$dat_severity = $var_ps;
    my \$dat_specific_problem = $var_sp;
    my \$dat_probable_cause = $var_pc;
    my \$dat_event_type = $var_EventType;
    my \$dat_managed_object = $mo;
    my \$dat_additional_text = "$addTxt";
    
    my \$dat_notification_id = $notification_id;
    my \$dat_correlated_notification_id = "";

    my \$agent_address = \$entrada->{"IPADDR"};
    my \$dat_event_time = \$llena->fecha();
    my \$hostname = HostRegex(\$config{"HOST"}, \$agent_address);
    
    ################################################################################### 
    
    #---------- (INICIO) Personalizacion del trap 
    
    ###################################################################################
END_SUB
        if (exists $alarmas_secundarias->{$alarm_name}) {
            foreach my $sec_alarm (keys %{$alarmas_secundarias->{$alarm_name}}) {
                my $oid_sec = $alarmas_secundarias->{$alarm_name}->{$sec_alarm};
                print $fh <<"END_SEC_ALARM";
    if (ifexists(\$entrada->{"$oid_sec"})) {
        \$dat_additional_text .= "\\n$sec_alarm = " . \$entrada->{"$oid_sec"} . ",\\n";
    }
END_SEC_ALARM
            }
        }

        print $fh <<"END_SUB";
    ################################################################################### 
    
    #---------- (TERMINO) Personalizacion del trap 
    
    ###################################################################################
    ################################################################################### 
    
    #----------  Llenado de campos de la alarma
    ###################################################################################

    \$llena->llenaMO("MO:" . \$dat_managed_object) if (ifexists(\$dat_managed_object));
    \$llena->llenaPC("PC:" . \$dat_probable_cause) if (ifexists(\$dat_probable_cause));
    \$llena->llenaSP("SP:" . \$dat_specific_problem) if (ifexists(\$dat_specific_problem));
    \$llena->llenaPS("PS:" . \$dat_severity) if (ifexists(\$dat_severity));
    \$llena->llenaNI("NID:" . \$dat_notification_id) if (ifexists(\$dat_notification_id));
    \$llena->llenaAT("AddTxt:" . \$dat_additional_text) if (ifexists(\$dat_additional_text));
    \$llena->EventTime("ETime:" . \$dat_event_time) if (ifexists(\$dat_event_time));
    \$llena->EventType("EType:" . \$dat_event_type) if (ifexists(\$dat_event_type));

    \$alarm_txt = \${ \$llena->{mensaje_x733} };
    \$llena->vacia_mensaje_x733();
    \$alarm_txt = "###START###" . \$alarm_txt . "###END###";

    return \$alarm_txt;
}

1;
END_SUB
        $notification_id++;
    }

    close $fh;
}

sub crear_archivos_genericos {
    # ...implementation...
}


1;
