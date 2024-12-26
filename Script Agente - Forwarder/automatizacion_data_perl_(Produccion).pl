#!/usr/bin/perl
use strict;
use warnings;
use Socket;
use File::Spec;
use File::stat;
use File::Basename;
use Data::Dumper;;

my $Ruta_raiz = "";


my $ruta_raiz_servidor = "/home/ump/scripts/CSV/";
my $ruta_agentes = "/opt/UMP/AGENTES/";
my $ruta_servicios = "/etc/systemd/system";
my $ruta_forwards = "/opt/UMP/FORWARDER/fwdconfig";
my $ruta_filial = $ruta_raiz_servidor .'FILIAL.csv';
#Declaracion de variables para archivos desordenados provisionales
my $ruta_prov1="";
my $ruta_prov2="";
my $ruta_csv = "/home/ump/scripts/CSV/agentes_info_con_servicio.csv";

# Rutas principales - Concatenar la ruta raiz con las rutas de los agentes, servicios y forwards
my $Ruta_principal_agentes = File::Spec->catdir($Ruta_raiz, $ruta_agentes);
my $Ruta_principal_servicios = File::Spec->catdir($Ruta_raiz, $ruta_servicios);
my $Ruta_principal_forwards = File::Spec->catdir($Ruta_raiz, $ruta_forwards);
# Funcion para obtener metadata de un agente
sub obtener_metadata {
    my ($nombre_agente, $ruta_completa, $tipo) = @_;

    my @stats = stat($ruta_completa);
    return unless @stats;  # Si no se pudo obtener el stat, retornar vacio

    my $fecha_creacion = $stats[10] ? localtime($stats[10]) : 'Desconocida';  # Fecha de creacion
    my $propietario = eval { getpwuid($stats[4]) } // 'Desconocido';          # Propietario
    my $grupo = eval { getgrgid($stats[5]) } // 'Desconocido';                # Grupo
    my $peso = defined $stats[7] ? $stats[7] : '0.1';  # Peso para archivo
    return {
        'Nombre' => $nombre_agente,
        'Ruta Agente' => $ruta_completa,
        'Tipo' => $tipo,
        'Fecha de Creacion' => $fecha_creacion,
        'Propietario' => $propietario,
        'Grupo' => $grupo,
        'Peso' => $peso,
    };
}

# Funcion para obtener detalles de los agentes
sub obtener_agentes {
    my ($ruta) = @_;

    # Chequeo si la ruta existe
    unless (-d $ruta) {
        warn "La ruta proporcionada no es un directorio valido: $ruta de la funcion obtener agentes";
        return;
    }

    # Arreglo para almacenar informacion de los agentes
    my @agentes_info;

    # Abrir la ruta del directorio
    opendir(my $dir, $ruta) or do {
        warn "No se pudo abrir el directorio de la funcion obtener agentes '$ruta': $!";
        return;
    };

    # Iterar sobre los elementos en el directorio
    while (my $entrada = readdir($dir)) {
        next if ($entrada eq '.' || $entrada eq '..'|| $entrada eq 'versiones');  # Ignorar entradas especiales

        my $ruta_completa = "$ruta/$entrada";
        my $tipo = -d $ruta_completa ? 'carpeta' : 'archivo';

        # Obtener metadata del agente
        my $info = eval { obtener_metadata($entrada, $ruta_completa, $tipo) };
        if ($@) {
            warn "Error en la funcion obtener_metadata: $@";
            next;
        }
        
        push @agentes_info, $info if $info;  # Agregar informacion al arreglo
    }

    closedir($dir);
    return \@agentes_info;  # Devolver referencia a array con la informacion
}
# Funcion para obtener propiedades del agente
sub propiedades_agente {
    my ($nombre_agente, $ruta_agente) = @_;

    # Arreglo para almacenar propiedades del agente
    
    my %propiedades;

    # Inicializar las columnas
    
    $propiedades{'Nombre'} = $nombre_agente;
    $propiedades{'Ruta Agente'} = $ruta_agente;
    $propiedades{'Notas'} = '';  # Inicializar campo de notas
    $propiedades{'Notas IP Puerto'} = '';  # Inicializar campo de notas IP y Puerto

    # Variables para almacenar archivos y validaciones
    
    my @archivos;
    my $agent_properties_exist = 'No';
    my ($ip, $puerto, $host, $severity) = ('Desconocida', 'Desconocido', '', '');

    my $tipo_agente = 'Desconocido';

    # Verificar si la ruta es un directorio
    
    unless (-d $ruta_agente) {
        warn "La ruta proporcionada '$ruta_agente' no es un directorio.";
        $propiedades{'Notas'} = "La ruta proporcionada '$ruta_agente' no es un directorio.";
        return \%propiedades;  # Retornar propiedades vacias en caso de error
    }

    # Abrir la ruta del directorio del agente
    
    opendir(my $dir, $ruta_agente) or do {
        if ($! =~ /Permission denied/) {
        
            $propiedades{'Notas'} = "No se pudo abrir el archivo ¡Permiso denegado!";
            $propiedades{'Notas IP Puerto'} = "No se pudo abrir el archivo ¡Permiso denegado!";
            $host = 'Permiso denegado';
            $severity = 'Permiso denegado';
            $ip = 'Permiso denegado';
            $puerto = 'Permiso denegado';
            $tipo_agente = 'Permiso denegado';
            $archivos[0] = 'Permiso denegado';
    
            $propiedades{'Archivos en Carpeta Raiz Agente'} = join("\n", @archivos);
            $propiedades{'AGENT PROPERTIES'} = $agent_properties_exist;
            $propiedades{'IP'} = $ip;
            $propiedades{'PUERTO'} = $puerto;
            $propiedades{'HOST'} = $host;
            $propiedades{'SEVERITY'} = $severity;
            $propiedades{'Tipo de Agente'} = $tipo_agente;
        
            warn "No se pudo abrir el directorio de la funcion propiedades agentes '$ruta_agente': Permiso denegado";
            $propiedades{'Notas'} = "No se pudo abrir el directorio '$ruta_agente': Permiso denegado";
        } else {
            warn "No se pudo abrir el directorio de la funcion propiedades agentes '$ruta_agente': $!";
            $propiedades{'Notas'} = "No se pudo abrir el directorio '$ruta_agente': $!";
        }
        return \%propiedades;  # Retornar propiedades vacias en caso de error
    };

    # Iterar sobre los elementos en el directorio del agente
    
    while (my $entrada = readdir($dir)) {
        next if ($entrada eq '.' || $entrada eq '..');  # Ignorar entradas especiales
        my $ruta_completa = "$ruta_agente/$entrada";
        next unless -f $ruta_completa;  # Ignorar si no es un archivo

        push @archivos, $entrada;  # Guardar el nombre del archivo

        # Verificar si existe un archivo .properties
        
        if ($entrada =~ /AGENT.properties$/) {
            $agent_properties_exist = 'Si';
            # Leer el archivo para encontrar IP, PUERTO, HOST y SEVERITY
            
            if (open my $fh, '<', $ruta_completa) {
                while (my $line = <$fh>) {
                    chomp $line;
                    next if $line =~ /^\s*#/;  # Omitir líneas comentadas
                    if ($line =~ /^localhost:=(.*)/ || $line =~ /^host:=(.*)/) {
                        my $new_ip = $1;
                        if ($ip ne 'Desconocida' && $ip eq $new_ip) {
                            warn "Error: Valores ciclicos detectados para IP.";
                            $propiedades{'Notas'} = "Error: Valores ciclicos detectados para IP.";
                            return \%propiedades;
                        }
                        $ip = $new_ip;  # Extraer IP
                    }
                    if ($line =~ /^localport:=(.*)/ || $line =~ /^port:=(.*)/) {
                        my $new_puerto = $1;
                        if ($puerto ne 'Desconocido' && $puerto eq $new_puerto) {
                            warn "Error: Valores ciclicos detectados para PUERTO.";
                            $propiedades{'Notas'} = "Error: Valores ciclicos detectados para PUERTO.";
                            return \%propiedades;
                        }
                        $puerto = $new_puerto;  # Extraer PUERTO
                    }
                    
                    if ($line =~ /^HOST:=(.*)/) {
                        $host = $1;  # Extraer HOST
                    }
                    if ($line =~ /^SEVERITY:=(.*)/) {
                        $severity = $1;  # Extraer SEVERITY
                    }
                }
                close $fh;
            } else {
                if ($! =~ /Permission denied/) {
                    # Instaciar todas las propiedades con un mensaje de error
                    warn "No se pudo abrir el archivo de la funcion propiedades agentes '$entrada': Permiso denegado";
                    $propiedades{'Notas'} = "No se pudo abrir el archivo '$entrada': Permiso denegado";
                } else {
                    warn "No se pudo abrir el archivo de la funcion propiedades agentes '$entrada': $!";
                    $propiedades{'Notas'} = "No se pudo abrir el archivo '$entrada': $!";
                }
            }
        }
    }

    # Verificar tipo de agente SNMP
    
    if (-d "$ruta_agente/ABR" && -f "$ruta_agente/ABR/SNMPAgente.pm") {
        $tipo_agente = 'SNMP';
        # Si aun no se encontro IP y PUERTO, buscar en SNMPAgente.pm
        if ($ip eq 'Desconocida' || $puerto eq 'Desconocido') {
            ($ip, $puerto) = extraer_ip_puerto_snmp($ruta_agente);
        }
    }
    # Verificar tipo de agente ASCII
    
    elsif (-d "$ruta_agente/ABR" && 
           (-f "$ruta_agente/ABR/ASCII.pm" || -f "$ruta_agente/ABR/ASCII_CI.pm" || -f "$ruta_agente/ABR/ASCII_WIN_CI.pm" || -f "$ruta_agente/ABR/ASCII_SS.pm")) {
        $tipo_agente = 'ASCII';
    }
    # Verificar tipo de agente CORBA
    
    elsif (-d "$ruta_agente/corba_agent" || -d "$ruta_agente/ior" || -d "$ruta_agente/corba_agent_bkp" || 
           (-d "$ruta_agente/config" && grep { /\.xml$/ && /crb_agent/ } glob("$ruta_agente/config/*"))) {
        $tipo_agente = 'CORBA';

        # Si no se encontró IP y PUERTO en archivos .properties, buscar en archivos crb_agent.xml
        
        if ($ip eq 'Desconocida' || $puerto eq 'Desconocido') {
            my @crb_files = glob("$ruta_agente/config/crb_agent*.xml");
            my (@ips, @puertos);

            foreach my $file (@crb_files) {
                if (open my $fh, '<', $file) {
                    while (my $line = <$fh>) {
                        chomp $line;
                        next if $line =~ /^\s*#/;  # Omitir líneas comentadas
                        if ($line =~ /<corba_if>(.*)<\/corba_if>/) {
                            push @ips, $1;
                        }
                        if ($line =~ /<consumer_port>(.*)<\/consumer_port>/) {
                            push @puertos, $1;
                        }
                    }
                    close $fh;
                } else {
                    warn "No se pudo abrir el archivo '$file': $!";
                }
            }

            $ip = join(" - ", @ips) if @ips;
            $puerto = join(" - ", @puertos) if @puertos;

            unless (@ips || @puertos) {
                $propiedades{'Notas IP Puerto'} = "No se pudo abrir los archivos crb_agent.xml o no se encontraron IPs y Puertos.";
            }
        }
    }

    # Verificar tipo de agente ASCII y extraer IP y PUERTO si faltan
    
    if ($tipo_agente eq 'ASCII' && ($ip eq 'Desconocida' || $puerto eq 'Desconocido')) {
        ($ip, $puerto) = extraer_ip_puerto_principal($ruta_agente, $nombre_agente);
        if ($ip eq 'Desconocida' && $puerto eq 'Desconocido') {
            ($ip, $puerto) = extraer_ip_puerto_config($ruta_agente, $nombre_agente);
        }
    }

    # Ultima validacion para IP asignar la ip del host
    
    if ($ip eq 'Desconocida') {
       # Ejecutar comando para obtener la IP del host  hostname -I 10.152.74.247 100.127.5.80 y extraer la primera IP
        $ip = `hostname -I`;
        chomp $ip;
        $ip = (split ' ', $ip)[0]; 
        $propiedades{'Notas IP Puerto'} .= "\nSe le asigna la IP del Local host";
    }


    closedir($dir);

    # Llenar las propiedades en el hash
    
    $propiedades{'Archivos en Carpeta Raiz Agente'} = join("\n", @archivos);
    $propiedades{'AGENT PROPERTIES'} = $agent_properties_exist;
    $propiedades{'IP'} = $ip;
    $propiedades{'PUERTO'} = $puerto;
    $propiedades{'HOST'} = $host;
    $propiedades{'SEVERITY'} = $severity;
    $propiedades{'Tipo de Agente'} = $tipo_agente;
    # Validar si IP y PUERTO son validos
    return \%propiedades;  # Retornar hash con propiedades del agente
}

# Funcion para extraer IP y PUERTO de un archivo principal Perl

sub extraer_ip_puerto_principal {
    my ($ruta_agente, $nombre_agente) = @_;
    my ($ip, $puerto) = ('Desconocida', 'Desconocido');

    # Buscar el archivo principal Perl
    
    opendir(my $dir, $ruta_agente) or do {
        warn "No se pudo abrir el directorio '$ruta_agente': $!";
        return ($ip, $puerto);
    };

    my @archivos_principales = grep { /^agt_.*\.pl$/ && !/bkp|backup|respaldo/i } readdir($dir);
    closedir($dir);
    # Seleccionar el archivo mas parecido al nombre del agente
    
    my $archivo_principal = (sort { length($a) <=> length($b) } @archivos_principales)[0];
    unless ($archivo_principal) {
        warn "No se encontro un archivo principal Perl en '$ruta_agente'";
        return ($ip, $puerto);
    }

    # Leer el archivo principal para extraer IP y PUERTO

    my $ruta_archivo_principal = "$ruta_agente/$archivo_principal";
    if (open my $fh, '<', $ruta_archivo_principal) {
        while (my $line = <$fh>) {
            chomp $line;
            if ($line =~ /thishost\s*=>\s*['"]?([\d\.]+)['"]?/) {
                $ip = $1;
            } elsif ($line =~ /thisport\s*=>\s*(\d+)/) {
                $puerto = $1;
            }  
            elsif ($line =~ /host\s*=>\s*['"]?([\d\.]+)['"]?/) {
                $ip = $1;
            } elsif ($line =~ /port\s*=>\s*(\d+)/) {
                $puerto = $1;
            }
            # Otra forma que pueda estar thisport my $variable = ABR::ASCII_SS -> new ( som_eom_file => "/opt/UMP/AGENTES/OBM_OVO_MEX/som_eom.abr", thisport => "6116");
            
            elsif ($line =~ /thisport\s*=>\s*['"]?(\d+)['"]?/) {
                $puerto = $1;
            } elsif ($line =~ /thishost\s*=>\s*['"]?([\d\.]+)['"]?/) {
                $ip = $1;
            } elsif ($line =~ /thisport\s*=>\s*(\d+)/) {
                $puerto = $1;
            } elsif ($line =~ /host\s*=>\s*['"]?([\d\.]+)['"]?/) {
                $ip = $1;
            } elsif ($line =~ /port\s*=>\s*(\d+)/) {
                $puerto = $1;
            }
        }
        close $fh;
    } else {
        warn "No se pudo abrir el archivo '$ruta_archivo_principal': $!";
    }
    return ($ip, $puerto);
}

# Funcion para extraer IP y PUERTO de SNMPAgente.pm
sub extraer_ip_puerto_snmp {
    my ($ruta_agente) = @_;
    my ($ip, $puerto) = ('Desconocida', 'Desconocido');
    my $archivo_snmp = "$ruta_agente/ABR/SNMPAgente.pm";

    if (-f $archivo_snmp) {
        if (open my $fh, '<', $archivo_snmp) {
            while (my $line = <$fh>) {
                chomp $line;
                next if $line =~ /^\s*#/;  # Omitir líneas comentadas
                if ($line =~ /\$local_port\s*=\s*(\d+)\s*;/) {
                    $puerto = $1;
                }
                if ($line =~ /my\s+\$hostname\s*=\s*["']([\d\.]+)["']\s*;/) {
                    $ip = $1;
                }
            }
            close $fh;
        } else {
            warn "No se pudo abrir el archivo '$archivo_snmp': $!";
        }
    } else {
        warn "El archivo '$archivo_snmp' no existe.";
    }

    return ($ip, $puerto);
}

# Funcion para extraer IP y PUERTO de un archivo de configuracion
sub extraer_ip_puerto_config {
    my ($ruta_agente, $nombre_agente) = @_;
    my (@ips, @puertos, @archivos_config);
    # Validacion si se busca desde la carpeta config o desde la raiz del agente
    my @buscar_raiz = 0;

    # Buscar todos los archivos de configuracion en la carpeta config
    my $config_dir = "$ruta_agente/config";
    if (-d $config_dir) {
        opendir(my $dir, $config_dir) or do {
            warn "No se pudo abrir el directorio de configuracion '$config_dir': $!";
            return ('Desconocida', 'Desconocido', 'No se encontraron archivos de configuracion');
        };
        # Filtrar archivos de configuracion config_*.abr*config
        @archivos_config = grep { /^config_.*\.abr$/i } readdir($dir);
        closedir($dir);
    }

    # Si no se encontraron archivos en la carpeta config, buscar en la raiz
    unless (@archivos_config) {
        warn "No se encontraron archivos de configuracion en '$config_dir', buscando en la raiz del agente.";
        opendir(my $dir, $ruta_agente) or do {
            warn "No se pudo abrir el directorio del agente '$ruta_agente': $!";
            return ('Desconocida', 'Desconocido', 'No se encontraron archivos de configuracion');
        };
        # Filtrar archivos de configuracion config solamente los que tengan extension .abr
        @archivos_config = grep { /^config.*\.abr$/i } readdir($dir);
        @buscar_raiz = 1;
        closedir($dir);

        unless (@archivos_config) {
            warn "No se encontraron archivos de configuracion en la raiz del agente '$ruta_agente'";
            return ('Desconocida', 'Desconocido', 'No se encontraron archivos de configuracion');
        }
    }
    # Validar que solo sean archivos de configuracion y no directorios
    foreach my $archivo_config (@archivos_config) {
        my ($ip, $puerto) = ('Desconocida', 'Desconocido');

        my $ruta_archivo_config = "$ruta_agente/config/$archivo_config";
        
        $ruta_archivo_config = "$ruta_agente/$archivo_config" unless -f $ruta_archivo_config;

        if (open my $fh, '<', $ruta_archivo_config) {
            while (my $line = <$fh>) {
                chomp $line;
                next if $line =~ /^\s*#/;  # Ignorar lineas comentadas
                if ($line =~ /this_host\s*:\s*([\d\.]+)/) {
                    $ip = $1;
                } elsif ($line =~ /this_port\s*:\s*(\d+)/) {
                    $puerto = $1;
                } elsif ($line =~ /host\s*:\s*([\d\.]+)/) {
                    $ip = $1;
                } elsif ($line =~ /port\s*:\s*(\d+)/) {
                    $puerto = $1;
                }
            }
            close $fh;
        } else {
            warn "No se pudo abrir el archivo '$ruta_archivo_config': $!";
        }

        push @ips, $ip;
        push @puertos, $puerto;
    }

    return (join(" - ", @ips), join(" - ", @puertos), join(" - ", @archivos_config));
}

# Funcion para obtener el estado de un servicio
sub obtener_estado_servicio {
    my ($nombre_servicio) = @_;
    my $estado = 'Desconocido';
    my $notas_servicio = '';

    my $output = `systemctl status $nombre_servicio 2>&1`;

    if ($output =~ /Active:\s+active \(running\)/) {
        $estado = 'RUNNING';
    } elsif ($output =~ /Active:\s+inactive \(dead\)/) {
        $estado = 'INACTIVE';
    } elsif ($output =~ /Active:\s+failed \(failed\)/) {
        $estado = 'FAILED';
    } else {
        $estado = 'UNKNOWN';
    }

    return ($estado, $notas_servicio);
}

# Funcion para obtener servicios    
sub obtener_servicios {
    my ($ruta_servicios) = @_;

    unless (-d $ruta_servicios) {
        warn "La ruta proporcionada no es un directorio valido: $ruta_servicios";
        return;
    }

    my %servicios_info;

    opendir(my $dir, $ruta_servicios) or do {
        warn "No se pudo abrir el directorio '$ruta_servicios': $!";
        return;
    };

    while (my $entrada = readdir($dir)) {
        next if ($entrada eq '.' || $entrada eq '..');

        my $ruta_completa = "$ruta_servicios/$entrada";
        next unless -f $ruta_completa;

        if ($entrada =~ /^agt_(.*)\.service$/) {
            my $nombre_servicio = $1;
            # Nombre completo del servicio con todo y extension
            my $nombre_servicio_completo = $entrada;
            my ($estado, $notas_servicio) = obtener_estado_servicio($entrada);

            push @{$servicios_info{lc($nombre_servicio)}}, {
                'Nombre servicio' => $nombre_servicio,
                'Nombre servicio extension' => $nombre_servicio_completo,
                'Ruta Servicio' => $ruta_completa,
                'Estado servicio' => $estado,
                'Notas servicio' => $notas_servicio,
            };
        }else {
            warn "El archivo '$entrada' no es un archivo de servicio valido.";
        } 
    }

    closedir($dir);
    return \%servicios_info;
}

# Funcion para obtener forwarders
sub buscar_forwarder {
    my ($ruta_forwards, $nombre_agente, $minusculas, $nombre_aproximado) = @_;

    # Chequeo si la ruta existe
    unless (-d $ruta_forwards) {
        warn "La ruta proporcionada no es un directorio valido: $ruta_forwards";
        return;
    }

    # Hash para almacenar informacion de los forwarders
    my %forwarders_info;

    # Abrir la ruta del directorio
    opendir(my $dir, $ruta_forwards) or do {
        warn "No se pudo abrir el directorio de la funcion buscar_forwarder '$ruta_forwards': $!";
        return;
    };

    # Iterar sobre los elementos en el directorio

    while (my $entrada = readdir($dir)) {
        next if ($entrada eq '.' || $entrada eq '..');  # Ignorar entradas especiales

        my $ruta_completa = "$ruta_forwards/$entrada";
        next unless -f $ruta_completa;  # Ignorar si no es un archivo

        if ($entrada =~ /^$nombre_agente.*_forwarder\.xml$/i) {
            push @{$forwarders_info{$nombre_agente}}, $ruta_completa;
        }
        if ($minusculas) {
            # Si las entradas son cero modificar el nombre del forwarder a minúsculas
            if (!keys %forwarders_info) {
                my $nombre_agente = lc($nombre_agente);
                # Entrada en minúsculas
                $entrada = lc($entrada);    
                # Si esta activo el nombre aproximado tomar el nombre y di
                if ($nombre_aproximado) {
                    # Recondiciar la entradas
                    $entrada = $entrada =~ /^([^_]*_[^_]*)_/;
                    if ($entrada =~ /^$nombre_agente.*_forwarder\.xml$/i) {
                        push @{$forwarders_info{$nombre_agente}}, $ruta_completa;
                    }
                } else {
                    if ($entrada =~ /^$nombre_agente.*_forwarder\.xml$/i) {
                        push @{$forwarders_info{$nombre_agente}}, $ruta_completa;
                    }
                }
            }
        }
    }

    closedir($dir);
    return \%forwarders_info;  # Devolver referencia a hash con la informacion
}


# Funcion para extraer informacion del forwarder
sub extraer_info_forwarder {
    my ($ruta_forwarder) = @_;

    my %info;
    if (open my $fh, '<', $ruta_forwarder) {
        while (my $line = <$fh>) {
            chomp $line;
            if ($line =~ /<forwarder_name>(.*)<\/forwarder_name>/) {
                $info{'FORWARDER NAME'} = $1;
            }
            if ($line =~ /<physical_path>(.*)<\/physical_path>/) {
                $info{'PHYSICAL PATH'} = $1;
            }
            if ($line =~ /<gluster_path>(.*)<\/gluster_path>/) {
                $info{'GLUSTER PATH'} = $1;
            }
            if ($line =~ /<remote_host>(.*)<\/remote_host>/) {
                $info{'REMOTE HOST'} = $1;
            }
            if ($line =~ /<remote_port>(.*)<\/remote_port>/) {
                $info{'REMOTE PORT'} = $1;
            }
            if ($line =~ /<tcp_timeout>(.*)<\/tcp_timeout>/) {
                $info{'TCP TIMEOUT'} = $1;
            }
            if ($line =~ /<final_path>(.*)<\/final_path>/) {
                $info{'FINAL PATH'} = $1;
            }
            if ($line =~ /<log_level>(.*)<\/log_level>/) {
                $info{'LOG LEVEL'} = $1;
            }
        }
        close $fh;
    } else {
        warn "No se pudo abrir el archivo de la funcion extraer_info_forwarder '$ruta_forwarder': $!";
    }

    return \%info;
}

# Uso del script

my $agentes_data = eval { obtener_agentes($Ruta_principal_agentes) };
if ($@) {
    die "Error en la funcion obtener_agentes: $@";
}

my $servicios_data = eval { obtener_servicios($Ruta_principal_servicios) };
if ($@) {
    die "Error en la funcion obtener_servicios: $@";
}
print Dumper($servicios_data);

my $forwarders_data = eval { buscar_forwarder($Ruta_principal_forwards) };
if ($@) {
    die "Error en la funcion buscar_forwarder: $@";
}

# Crear un hash para almacenar las propiedades de los agentes

my $agentes_prop = {};

if ($agentes_data) {
    # Anexar propiedades para cada agente
    
    foreach my $agente (@$agentes_data) {
        my $nombre_agente = $agente->{'Nombre'};
        my $ruta_agente = $agente->{'Ruta Agente'};
        # Obtener propiedades del agente y anexarlas al agente_data
        
        my $propiedades = eval { propiedades_agente($nombre_agente, $ruta_agente) };
        if ($@) {
            warn "Error en la funcion propiedades_agente: $@";
            next;
        }
        # Guardar las propiedades en el hash
        
        $agentes_prop->{$nombre_agente} = $propiedades;  # Guardar propiedades en el hash
    }
} else {
    print "No se encontraron agentes o hubo un error.\n";
}

# Unir los datos de los agentes y sus propiedades - tomando como referencia el nombre del agente y en caso de no existir propiedades, se asigna un hash vacio

my $agentes_info = { map { $_->{'Nombre'} => { %{$_}, %{ $agentes_prop->{$_->{'Nombre'}} // {} } } } @$agentes_data };

# Anexar el nombre del servicio del agente a los datos del agente
my $agentes_info_con_servicio = { 
    map { 
        my $agente = $_;
        my $nombre_agente = lc($agente);
        my @nombre_extesion = map { $_->{'Nombre servicio extension'} } grep { $_->{'Nombre servicio'} =~ /^$nombre_agente/ } map { @$_ } values %$servicios_data;
        my @servicios = map { "$_->{'Estado servicio'} -> $_->{'Nombre servicio'}" } grep { $_->{'Nombre servicio'} =~ /^$nombre_agente/ } map { @$_ } values %$servicios_data;
        my @notas_servicio = map { $_->{'Notas servicio'} } grep { $_->{'Nombre servicio'} =~ /^$nombre_agente/ } map { @$_ } values %$servicios_data;
        my @ruta_servicio = join("\n", map { $_->{'Ruta Servicio'} } grep { $_->{'Nombre servicio'} =~ /^$nombre_agente/ } map { @$_ } values %$servicios_data);
        my @estado_servicio = join("\n", map { $_->{'Estado servicio'} } grep { $_->{'Nombre servicio'} =~ /^$nombre_agente/ } map { @$_ } values %$servicios_data); 
        # Si no se encontraron servicios, intentar con el nombre en mayusculas
        if (!@servicios) {
            $nombre_agente = uc($agente);
            @nombre_extesion = map { $_->{'Nombre servicio extension'} } grep { $_->{'Nombre servicio'} =~ /^$nombre_agente/ } map { @$_ } values %$servicios_data;
            @servicios = map { "$_->{'Estado servicio'} -> $_->{'Nombre servicio'}" } grep { $_->{'Nombre servicio'} =~ /^$nombre_agente/ } map { @$_ } values %$servicios_data;
            @notas_servicio = map { $_->{'Notas servicio'} } grep { $_->{'Nombre servicio'} =~ /^$nombre_agente/ } map { @$_ } values %$servicios_data;
            @ruta_servicio = join("\n", map { $_->{'Ruta Servicio'} } grep { $_->{'Nombre servicio'} =~ /^$nombre_agente/ } map { @$_ } values %$servicios_data);
            @estado_servicio = join("\n", map { $_->{'Estado servicio'} } grep { $_->{'Nombre servicio'} =~ /^$nombre_agente/ } map { @$_ } values %$servicios_data);
        }
        # Ultima comprobacion si no se encontraron servicios
        if (!@servicios) {
            my ($nombre_agente_part) = split(/_/, $nombre_agente, 2);
            #print "No se encontraron servicios para el agente '$nombre_agente_part'.\n";
            foreach my $servicio (map { @$_ } values %$servicios_data) {
                # Separar el nombre del agente y del servicio
                my ($nombre_servicio_part) = split(/_/, $servicio->{'Nombre servicio'}, 2);
                # Transformar el nombre del servicio a minúsculas
                $nombre_servicio_part = lc($nombre_servicio_part);
                # Valudar si no contiene datos cambiar el nombre a minusculas
                if ($nombre_agente_part eq $nombre_servicio_part) {
                    push @nombre_extesion, $servicio->{'Nombre servicio extension'};
                    push @servicios, "$servicio->{'Estado servicio'} -> $servicio->{'Nombre servicio'}";
                    push @notas_servicio, $servicio->{'Notas servicio'};
                    push @ruta_servicio, $servicio->{'Ruta Servicio'};
                    push @estado_servicio, $servicio->{'Estado servicio'};
                }
                # Validar si no se encontraron servicios para el agente cambiar el nombre a minusculas
                if (!@servicios) {
                    $nombre_agente_part = lc($nombre_agente_part);
                    if ($nombre_agente_part eq $nombre_servicio_part) {
                        push @nombre_extesion, $servicio->{'Nombre servicio extension'};
                        push @servicios, "$servicio->{'Estado servicio'} -> $servicio->{'Nombre servicio'}";
                        push @notas_servicio, $servicio->{'Notas servicio'};
                        push @ruta_servicio, $servicio->{'Ruta Servicio'};
                        push @estado_servicio, $servicio->{'Estado servicio'};
                        }     
                }
            }
        }
                
        # Validaciones especiales - dado la naturaleza de su nombre 
        if ($nombre_agente eq 'CISCOPRIME_AGT_PRI' || $nombre_agente eq 'ciscoprime_agt_pri' || $nombre_agente eq 'ciscoprime') {
            # Asignarle el servicio cisco_pri - al agente 
            my $servicio_cisco = 'cisco_pri';
            my $servicio_cisco_extension = 'agt_cisco_pri.service';
            my ($estado, $notas_servicio) = obtener_estado_servicio($servicio_cisco_extension);
            # Concatenar a las notas de servicio el estado del servicio
            $notas_servicio .= "Servicio estraido de forma manual (Caso especial)."; 
             push @nombre_extesion, $servicio_cisco_extension;
            push @servicios, "$estado -> $servicio_cisco";
            push @notas_servicio, $notas_servicio;
            push @ruta_servicio, $Ruta_principal_servicios . "/$servicio_cisco_extension";
            push @estado_servicio, $estado;
        }  
        $agente => {
            %{ $agentes_info->{$agente} }, 
            'Estado Servicio' => join("\n", @servicios),
            'Notas servicio' => join("\n", @notas_servicio),
            'Ruta Servicio' => join("\n", @ruta_servicio),
            'Servicio' => join("\n", @nombre_extesion),
        } 
    } keys %$agentes_info 
};

# Anexar informacion del forwarder al agente
# Función para anexar información del forwarder al agente
sub anexar_info_forwarder {
    my ($agentes_info_con_servicio, $Ruta_principal_forwards) = @_;
    # Hash que almacenara los forwarders asociados a los agentes
    my $agentes_info_con_forwarder = {};

    foreach my $agente (keys %$agentes_info_con_servicio) {
        my $nombre_forwarder = $agente;
        my $forwarders_data = buscar_forwarder($Ruta_principal_forwards, $nombre_forwarder);
        if ($forwarders_data && %$forwarders_data) {
            procesar_forwarders($agentes_info_con_servicio, $agente, $forwarders_data, $nombre_forwarder);
            # Añadir al hash de agentes con forwarder
            $agentes_info_con_forwarder->{$agente} = $agentes_info_con_servicio->{$agente};
        } else {
            # Buscar forwarders en minúsculas
            $nombre_forwarder = lc($agente);
            $forwarders_data = buscar_forwarder($Ruta_principal_forwards, $nombre_forwarder, 1);
            if (!$forwarders_data || !%$forwarders_data) {

                # Recortar hasta el segundo guion bajo
                
                my ($nombre_agente_part) = $nombre_forwarder =~ /^([^_]*_[^_]*)_/;
                $nombre_agente_part = lc($nombre_agente_part);

                # Validar el nombre si se encuentra vacio asignar el nombre del agente original

                if (!$nombre_agente_part) {
                    $nombre_agente_part = $nombre_forwarder;
                }
                $forwarders_data = buscar_forwarder($Ruta_principal_forwards, $nombre_agente_part, 1, 1);
                if ($forwarders_data && %$forwarders_data) {
                    procesar_forwarders($agentes_info_con_servicio, $agente, $forwarders_data, $nombre_agente_part);

                    # Añadir al hash de agentes con forwarder

                    $agentes_info_con_forwarder->{$agente} = $agentes_info_con_servicio->{$agente};

                } else {
                    # Validación adicional: recortar hasta el primer guion bajo

                    ($nombre_agente_part) = $nombre_forwarder =~ /^([^_]*)_/;
                    $nombre_agente_part = lc($nombre_agente_part);
                    if (!$nombre_agente_part) {
                        $nombre_agente_part = $nombre_forwarder;
                    }
                    $forwarders_data = buscar_forwarder($Ruta_principal_forwards, $nombre_agente_part, 1, 1);

                    if ($forwarders_data && %$forwarders_data) {
                        procesar_forwarders($agentes_info_con_servicio, $agente, $forwarders_data, $nombre_agente_part);

                        # Añadir al hash de agentes con forwarder

                        $agentes_info_con_forwarder->{$agente} = $agentes_info_con_servicio->{$agente};
                    } else {

                        asignar_forwarder_no_encontrado($agentes_info_con_servicio, $agente, $nombre_agente_part);
                    }
                }
            }
        }
        # Validaciones especiales - dado la naturaleza de su nombre  (TEKELEC_REPORTES)
        if ($agente eq 'TEKELEC_REPORTES' || $agente eq 'tekelec_reportes') {
            # Asignarle el servicio tekelec_reportes - al agente 
            my $servicio_tekelec = 'tekelec_reportes';
            my $servicio_tekelec_extension = 'agt_tekelec_reportes.service';
            my ($estado, $notas_servicio) = obtener_estado_servicio($servicio_tekelec_extension);
            # Concatenar a las notas de servicio el estado del servicio
            $notas_servicio .= "Servicio estraido de forma manual (Caso especial).";
            $agentes_info_con_servicio->{$agente}->{'NOMBRE DEL SERVICIO DEL FORWARDER'} = $servicio_tekelec;
            $agentes_info_con_servicio->{$agente}->{'RUTA FORWARDER'} = $Ruta_principal_forwards . "/$servicio_tekelec_extension";
            $agentes_info_con_servicio->{$agente}->{'PHYSICAL PATH'} = 'No encontrado';
            $agentes_info_con_servicio->{$agente}->{'GLUSTER PATH'} = 'No encontrado';
            $agentes_info_con_servicio->{$agente}->{'REMOTE HOST'} = 'No encontrado';
            $agentes_info_con_servicio->{$agente}->{'REMOTE PORT'} = 'No encontrado';
            $agentes_info_con_servicio->{$agente}->{'FINAL PATH'} = 'No contiene - final path';
            $agentes_info_con_servicio->{$agente}->{'NOTAS FORWARDER'} = $notas_servicio;
            # Procesar información del forwarder
            procesar_forwarders($agentes_info_con_servicio, $agente, { $servicio_tekelec => ["$Ruta_principal_forwards/$servicio_tekelec_extension"] }, $servicio_tekelec);
            
        }
    }
}

# Función para procesar forwarders
sub procesar_forwarders {
    my ($agentes_info_con_servicio, $agente, $forwarders_data, $nombre_forwarder) = @_;
    my @forwarder_files = @{$forwarders_data->{$nombre_forwarder}};
    my @forwarder_info;
    my @notas_forwarder;

    foreach my $forwarder_file (@forwarder_files) {
        my $info = eval { extraer_info_forwarder($forwarder_file) };
        if ($@) {
            warn "Error en la funcion extraer_info_forwarder: $@";
            push @notas_forwarder, "Error al extraer informacion del forwarder: $@";
            next;
        }
        push @forwarder_info, $info;
    }
    
    $agentes_info_con_servicio->{$agente}->{'NOMBRE DEL SERVICIO DEL FORWARDER'} = join(" - ", map { $_->{'FORWARDER NAME'} // 'No encontrado' } @forwarder_info);
    $agentes_info_con_servicio->{$agente}->{'RUTA FORWARDER'} = join(" - ", @forwarder_files);
    $agentes_info_con_servicio->{$agente}->{'PHYSICAL PATH'} = join(" - ", map { $_->{'PHYSICAL PATH'} // 'No encontrado' } @forwarder_info);
    $agentes_info_con_servicio->{$agente}->{'GLUSTER PATH'} = join(" - ", map { $_->{'GLUSTER PATH'} // 'No encontrado' } @forwarder_info);
    $agentes_info_con_servicio->{$agente}->{'REMOTE HOST'} = join(" - ", map { $_->{'REMOTE HOST'} // 'No encontrado' } @forwarder_info);
    $agentes_info_con_servicio->{$agente}->{'REMOTE PORT'} = join(" - ", map { $_->{'REMOTE PORT'} // 'No encontrado' } @forwarder_info);
    $agentes_info_con_servicio->{$agente}->{'FINAL PATH'} = join(" - ", map { $_->{'FINAL PATH'} // 'No contiene - final path' } @forwarder_info);
    $agentes_info_con_servicio->{$agente}->{'NOTAS FORWARDER'} = join(" - ", @notas_forwarder);
}

# Función para asignar valores cuando no se encuentra el forwarder
sub asignar_forwarder_no_encontrado {
    my ($agentes_info_con_servicio, $agente, $nombre_agente_part) = @_;
    $agentes_info_con_servicio->{$agente}->{'NOMBRE DEL SERVICIO DEL FORWARDER'} = 'No se encontro forwarder';
    $agentes_info_con_servicio->{$agente}->{'RUTA FORWARDER'} = 'No se encontro forwarder';
    $agentes_info_con_servicio->{$agente}->{'PHYSICAL PATH'} = 'No se encontro forwarder';
    $agentes_info_con_servicio->{$agente}->{'GLUSTER PATH'} = 'No se encontro forwarder';
    $agentes_info_con_servicio->{$agente}->{'REMOTE HOST'} = 'No se encontro forwarder';
    $agentes_info_con_servicio->{$agente}->{'REMOTE PORT'} = 'No se encontro forwarder';
    $agentes_info_con_servicio->{$agente}->{'FINAL PATH'} = 'No se encontro forwarder';
    $agentes_info_con_servicio->{$agente}->{'NOTAS FORWARDER'} = 'No se encontro forwarder';
    warn "No se encontraron forwarders para el agente '$nombre_agente_part'.\n";
}

# Llamada a la función para anexar información del forwarder
anexar_info_forwarder($agentes_info_con_servicio, $Ruta_principal_forwards);



# Funcion para leer el archivo FILIAL.csv
sub leer_filial_csv {
    my ($ruta_csv) = @_;
    my %filial_info;

    open my $fh, '<', $ruta_csv or do {
        warn "No se pudo abrir el archivo '$ruta_csv': $!";
        return \%filial_info;
    };

    my $header = <$fh>;
    unless ($header) {
        warn "El archivo '$ruta_csv' está vacío o no se pudo leer la cabecera.";
        close $fh;
        return \%filial_info;
    }

    chomp $header;
    my @columnas = split /,/, $header;

    while (my $linea = <$fh>) {
        chomp $linea;
        my @valores = split /,/, $linea;
        if (@valores != @columnas) {
            warn "Número de columnas inconsistente en la línea $. del archivo '$ruta_csv'.";
            next;
        }
        my %registro;
        @registro{@columnas} = @valores;
        my $agente = $registro{'AGENTE'};
        $filial_info{$agente} = \%registro;
    }

    close $fh;
    return \%filial_info;
}

# Fusionar la informacion de FILIAL.csv con agentes_info_con_servicio

sub fusionar_informacion {
    my ($agentes_info, $filial_info) = @_;
    my $hostname = qx(hostname);
    chomp($hostname);
    foreach my $agente (keys %$agentes_info) {
        if (exists $filial_info->{$agente}) {
            my $info_filial = $filial_info->{$agente};
            $agentes_info->{$agente}->{'FILIAL'} = $info_filial->{'FILIAL'} // 'Desconocido FILIAL';
            # Tomar el archivo filiar como bus
            #$agentes_info->{$agente}->{'BUS'} = $info_filial->{'BUS'} // 'Desconocido BUS';
            # Tomar el hostname del servidor y asignarlo al campo BUS
            $agentes_info->{$agente}->{'BUS'} = $hostname // 'Desconocido BUS';
        } else {
            $agentes_info->{$agente}->{'FILIAL'} = 'Desconocido FILIAL';
            $agentes_info->{$agente}->{'BUS'} = 'Desconocido BUS';
        }
    }
}

# Añexar la informacion de FILIAL.csv a los agentes

my $filial_info = leer_filial_csv($ruta_filial);

fusionar_informacion($agentes_info_con_servicio, $filial_info);

# Funcion para validar y completar datos

sub validar_y_completar_datos {
    my ($data) = @_;
    # Hash vacio para almacenar la informacion de los agentes ordenada por columnas

    my %agentes_info;

    
    # Obtener todas las columnas existentes
    my %columnas;
    foreach my $agente (values %$data) {
        $columnas{$_} = 1 for keys %$agente;
    }
    my @columnas = sort keys %columnas;

    # Filtrar todos los agentes que sean archivos y no carpetas

    my @agentes = grep { $data->{$_}{'Tipo'} eq 'archivo' } keys %$data;
    foreach my $agente (@agentes) {
        delete $data->{$agente};
    }
        # Eliminar caracteres especiales de las columnas \n, \r, \t en caso de se encuentren concatenarlos el la misma celda
    
    foreach my $agente (keys %$data) {
        foreach my $columna (@columnas) {
            my $valor = $data->{$agente}{$columna};
            $valor = '' unless defined $valor;
            $valor =~ s/[\n\r\t]/ /g;
            $data->{$agente}{$columna} = $valor;
        }
    }
    # Extraer el nombre de las columnas y asignarlas al nuevo hash 

    foreach my $agente (keys %$data) {
        my @valores = map { $data->{$agente}{$_} } @columnas;
        $agentes_info{$agente} = \@valores;

        # Asinar los nombres como key a los valores ya establecidos

    }

    # Retornar las columnas ordenadas y la data validada
    return @columnas, $agentes_info;
}

# Funcion para guardar informacion en un archivo CSV

sub guardar_en_csv {
    my ($data, $ruta_csv) = @_;
    
    # Validar y completar datos
    my (@columnas, @data_actualizada);
    eval {
        (@columnas, @data_actualizada) = validar_y_completar_datos($data);
    };
    if ($@) {
        warn "Error al validar y completar datos: $@";
        return;
    }

    # Abrir el archivo CSV para escritura

    open my $fh, '>', $ruta_csv or do {
        warn "No se pudo abrir el archivo '$ruta_csv' para escritura: $!";
        return;
    };
    
    # Escribir la cabecera

    eval {
        print $fh join(',', @columnas) . "\n";
    };
    if ($@) {
        warn "Error al escribir la cabecera en el archivo CSV: $@";
        close $fh;
        return;
    }
    
    # Escribir los datos

    eval {
        foreach my $agente (sort keys %$data) {
            my @valores = map { 
                my $valor = $data->{$agente}{$_};
                if ($_ eq 'Ruta Servicio' || $_ eq 'Servicios' || $_ eq 'Notas servicio' || $_ eq 'Estado Servicio') {
                    $valor =~ s/ /\ - /g;  # Reemplazar espacios por -
                }
                $valor;
            } @columnas;
            print $fh join(',', @valores) . "\n";
        }
    };
    if ($@) {
        warn "Error al escribir los datos en el archivo CSV: $@";
        close $fh;
        return;
    }
    
    close $fh or warn "No se pudo cerrar el archivo '$ruta_csv': $!";

}

# Solicitar al usuario la ruta de guardado del archivo CSV


#En caso de tener contenido, se concatena con los nombres de archivos
if ($ruta_csv) {
    $ruta_prov1 = $ruta_raiz_servidor . "prov1.csv";
    $ruta_prov2 = $ruta_raiz_servidor . "ReporteAgentesyForwarders.csv";

} else {
    #De estar vacia, simplemente es el nombre del archivo
    $ruta_prov1 = "prov1.csv";
    $ruta_prov2 = "CSV/ReporteAgentesyForwarders.csv";
}

# Guardar los datos en el archivo CSV
guardar_en_csv($agentes_info_con_servicio, $ruta_csv);
my @columnas = validar_y_completar_datos($agentes_info_con_servicio);
#
#Dar formato reordenando columnas y eliminando informacion no relevante
system("awk 'BEGIN {FS=OFS=\",\"} {print \$5, \$3, \$30, \$14, \$11, \$19, \$16, \$28, \$4, \$17, \$1, \$10, \$2, \$21, \$9, \$12, \$22, \$23, \$8, \$18, \$6, \$13, \$25, \$24, \$26, \$7, \$15, \$20, \$27, \$29, \$31}' $ruta_csv > $ruta_prov1");
system("awk -F',' '{ \$26=\"\"; \$27=\"\"; \$28=\"\"; \$29=\"\"; \$30=\"\"; \$31=\"\"; print \$0 }' OFS=',' $ruta_prov1 > $ruta_prov2");
system("rm $ruta_csv");
system("rm $ruta_prov1");
