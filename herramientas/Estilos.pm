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

our $entry_bg_color_snmp = '#7a748e';
our $entry_fg_color_snmp = '#f2e6da';

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

# Estilos para botones modernos
our $modern_button_bg = '#4CAF50';  # Green
our $modern_button_fg = 'white';
our $modern_button_active_bg = '#45a049';  # Darker green
our $modern_button_active_fg = 'white';
our $modern_button_font = ['Helvetica', 16, 'bold'];

# Estilos para botones de siguiente paso
our $next_button_bg = '#f44336';  # Red
our $next_button_fg = 'white';
our $next_button_active_bg = '#e53935';  # Darker red
our $next_button_active_fg = 'white';
our $next_button_font = ['Helvetica', 16, 'bold'];

# Entry  
our $entry_font = ['Verdana', 16, 'bold'];

# Scrollbar

# Variable: -troughcolor (Color del canal de fondo del scroll)
our $scroll_trough_color_snmp = '#53546e';  # Slate Indigo, un tono oscuro pero neutro para destacar.

# Variable: -background (Color de fondo del scroll)
our $scroll_bg_color_snmp = '#f2e6da';  # Soft Cream, un tono claro para mantener suavidad y legibilidad.

# Variable: -foreground (Color del scroll mismo)
our $scroll_fg_color_snmp = '#302c44';  # Deep Plum, un color oscuro que contrasta bien con el fondo.

# Estilos para el registro de directorios
our $bg_color_directory = '#e5d0bf';
our $fg_color_directory = '#302c44';
our $button_color_directory = '#7a748e';
our $activebackground_button_color_directory = '#5e5673';
our $activeforeground_button_color_directory = '#f2e6da';
our $label_font_directory = ['Arial', 16, 'bold'];
our $input_font_directory = ['Arial', 14];
our $entry_font_snmp = ['Courier', 14, 'bold'];

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
    $modern_button_bg $modern_button_fg $modern_button_active_bg $modern_button_active_fg $modern_button_font
    $next_button_bg $next_button_fg $next_button_active_bg $next_button_active_fg $next_button_font
);

1;  # Finalizar el módulo con un valor verdadero