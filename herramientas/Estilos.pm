package herramientas::Estilos;
use strict;
use warnings;
use Tk;
use Exporter 'import';

# Estilos de la aplicación

# Paleta de colores
our $bg_color = '#723185';
our $fg_color = 'white';
our $button_color = '#5b2b6e';
our $insertbackground = '#302c44';
# Paleta de colores snmp (Domine el violeta - obscuro)
our $bg_color_snmp = '#302c44';
our $fg_color_snmp = '#e5d0bf';

our $button_color_snmp = '#b0a6b8';
our $bg_button_color_snmp = '#7a748e';
our $fg_button_color_snmp = '#f2e6da';
our $activebackground_button_color_snmp = '#5e5673';
our $activeforeground_button_color_snmp = '#f2e6da';

our $label_color_snmp = '#e5d0bf';
our $label_fg_color_snmp = '#302c44';

# Estilo de fuente para los input
our $input_font = ['Verdana', 16, 'bold'];
# Estilo de fuente para los input SNMP
our $input_font_snmp = ['Courier', 20, 'bold'];

# Estilo de fuente para las etiquetas
our $label_font = ['Verdana', 16, 'bold'];
# Estilo de fuente para las etiquetas SNMP
our $label_font_snmp = ['Courier', 16, 'bold'];

# Estilo de fuente para los botones
our $button_font = ['Verdana', 16, 'bold'];
# Estilo de fuente para los botones SNMP
our $button_font_snmp = ['Courier', 12, 'bold'];

# Estilo de fuente para los botones de la barra de herramientas
our $toolbar_button_font = ['Verdana', 12, 'bold'];

# Estilo de fuente para los botones de agentes
our $agents_button_font = ['Verdana', 16, 'bold'];

# Estilos para el registro de directorios
our $bg_color_directory = '#e5d0bf';
our $fg_color_directory = '#302c44';
our $button_color_directory = '#7a748e';
our $activebackground_button_color_directory = '#5e5673';
our $activeforeground_button_color_directory = '#f2e6da';
our $label_font_directory = ['Arial', 16, 'bold'];
our $input_font_directory = ['Arial', 14];

# Styles for alert windows
our $bg_color_success = '#28a745';
our $bg_color_error = '#dc3545';
our $bg_color_warning = '#ffc107';
our $bg_color_info = '#17a2b8';
our $bg_color_question = '#007bff';
our $label_font_alert = ['Verdana', 14, 'bold'];

# Export all variables
our @EXPORT_OK = qw(
    $bg_color $fg_color $button_color $label_font $button_font $toolbar_button_font $agents_button_font
    $bg_color_directory $fg_color_directory $button_color_directory $activebackground_button_color_directory
    $activeforeground_button_color_directory $label_font_directory $input_font_directory
    $bg_color_success $bg_color_error $bg_color_warning $bg_color_info $bg_color_question $label_font_alert
);

1;  # Finalizar el módulo con un valor verdadero