use strict;
use warnings;

# Hash para almacenar información de los agentes (ejemplo de uso)
my %agentes_info_con_servicio = (
    'AGENTE_1' => {},
    'AGENTE_2' => {},
    'AGENTE_3' => {}
);

# Función para cargar datos desde un archivo CSV
sub cargar_datos_agentes {
    my ($archivo) = @_;
    
    open my $fh, '<', $archivo or die "No se pudo abrir '$archivo': $!";
    
    # Leer la cabecera
    my $header = <$fh>;
    chomp $header;  # Eliminar el salto de línea
    my @columnas = split /,/, $header;  # Dividir la cabecera en columnas

    my %datos_agentes;
    
    # Leer líneas del archivo
    while (my $linea = <$fh>) {
        chomp $linea;  # Eliminar el salto de línea
        my @valores = split /,/, $linea;  # Dividir la línea en valores
        
        # Asumir que las columnas son: NOMBRE_AGENTE, FILIAL, BUS
        my $nombre_agente = $valores[0];
        $datos_agentes{$nombre_agente} = {
            'FILIAL' => $valores[1],
            'BUS' => $valores[2],
        };
    }
    
    close $fh;
    return \%datos_agentes;  # Devolver el hash de datos de agentes
}

# Cargar datos de agentes desde el archivo CSV
my $datos_agentes = cargar_datos_agentes('scripts/FILIAL.csv');

# Integrar los datos en el hash de agentes
foreach my $nombre_agente (keys %$datos_agentes) {
    print "Procesando agente: $nombre_agente\n";
}

# Imprimir el contenido del hash final para verificar
use Data::Dumper;
print Dumper(\%agentes_info_con_servicio);