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

our $entry_bg = '#f0f0f0';
our $entry_fg = '#000000';

# Nueva paleta de colores (Arboles)
our $corteza_marron = '#8B4513';
our $hoja_verde = '#228B22';
our $wood_beige = '#D2B48C';
our $dark_moss = '#556B2F';
our $pine_green = '#01796F';
our $forest_shadow = '#2E3D30';
our $amarillo_savia = '#FFD700';
our $rojo_otono = '#A52A2A';
our $twilight_grey = '#696969';
our $soil_black = '#1C1C1C';

# Nueva paleta de colores (Rosa Pink)
our $rosa_pink = '#FFC0CB';
our $rosa_pink_oscuro = '#FF1493';
our $rosa_pink_claro = '#FF69B4';
our $rosa_pink_medio = '#FFC0CB';
our $rosa_pink_palo = '#FF91A4';



# Estilo de fuente para los input
our $input_font = ['Verdana', 16, 'bold'];
# Estilo de fuente para los input SNMP
our $input_font_snmp = ['Courier', 20, 'bold'];

# Estilo de fuente para las etiquetas
our $label_font = ['Verdana', 16, 'bold'];
our $label_bg_color = '#302c44';
our $label_fg_color = '#e5d0bf';
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

# ComboBox
our $combo_box_bg = '#f0f0f0';
our $combo_box_fg = '#000000';
our $combo_box_active_bg = '#5e5673';
our $combo_box_active_fg = '#f2e6da';

# Styles for alert windows
our $bg_color_success = '#28a745';
our $bg_color_error = '#dc3545';
our $bg_color_warning = '#ffc107';
our $bg_color_info = '#17a2b8';
our $bg_color_question = '#007bff';
our $label_font_alert = ['Verdana', 14, 'bold'];

# Estilos para la ventana de selección de archivos MIB
our $mib_selection_bg = '#f0f0f0';
our $mib_selection_fg = '#000000';
our $mib_selection_button_bg = '#4CAF50';
our $mib_selection_button_fg = 'white';
our $mib_selection_button_active_bg = '#45a049';
our $mib_selection_button_active_fg = 'white';
our $mib_selection_button_font = ['Helvetica', 12, 'bold'];
our $mib_selection_label_font = ['Arial', 14, 'bold'];
our $mib_selection_checkbutton_font = ['Arial', 12];

# Styles for modern and scrollable table
our $table_bg = '#f0f0f0';
our $table_fg = '#000000';
our $table_header_bg = '#4CAF50';
our $table_header_fg = 'white';
our $table_row_bg = '#ffffff';
our $table_row_alt_bg = '#f9f9f9';
our $table_font = ['Arial', 12];
our $table_header_font = ['Helvetica', 20, 'bold'];
# Checkbutton
our $checkbutton_bg = '#f0f0f0';
our $checkbutton_fg = '#000000';
our $checkbutton_active_bg = '#5e5673';
our $checkbutton_active_fg = '#f2e6da';
our $checkbutton_font = ['Arial', 12];


our $checkbox_selectcolor = '#302c44';
our $checkbox_bg = '#f0f0f0';
our $checkbox_fg = '#000000';
our $checkbox_active_bg = '#5e5673';
our $checkbox_active_fg = '#f2e6da';

# Save button
our $save_button_bg = '#4CAF50';
our $save_button_fg = 'white';
our $save_button_active_bg = '#45a049';
our $save_button_active_fg = 'white';
our $save_button_font = ['Helvetica', 12, 'bold'];



our $row_bg = '#f0f0f0';
our $row_fg = '#000000';
our $row_font = ['Arial', 12];

# Titles
our $title_font = ['Arial', 24, 'bold'];
our $title_bg = '#302c44';
our $title_fg = '#e5d0bf';

# Footer
our $footer_font = ['Arial', 12, 'bold'];
our $footer_button_font = ['Arial', 12, 'bold'];
our $footer_bg = '#302c44';
our $footer_fg = '#e5d0bf';
our $footer_button_bg = '#7a748e';
our $footer_button_fg = '#f2e6da';
our $footer_button_active_bg = '#5e5673';
our $footer_button_active_fg = '#f2e6da';

# Navigation
our $nav_bg = '#302c44';
our $nav_fg = '#e5d0bf';
our $nav_button_bg = '#7a748e';
our $nav_button_fg = '#f2e6da';
our $nav_button_active_bg = '#5e5673';
our $nav_button_active_fg = '#f2e6da';
our $nav_button_font = ['Arial', 12, 'bold'];

# Result
our $result_bg = '#f0f0f0';
our $result_fg = '#000000';


# Header
our $header_bg = '#302c44';
our $header_fg = '#e5d0bf';
our $header_font = ['Arial', 16, 'bold'];

# Buttons cancel and back
our $cancel_button_bg = '#f44336';
our $cancel_button_fg = 'white';
our $cancel_button_active_bg = '#e53935';
our $cancel_button_active_fg = 'white';
our $cancel_button_font = ['Helvetica', 16, 'bold'];


# Export all variables
our @EXPORT_OK = qw(
    $bg_color $fg_color $button_color $label_font $button_font $toolbar_button_font $agents_button_font
    $bg_color_directory $fg_color_directory $button_color_directory $activebackground_button_color_directory
    $activeforeground_button_color_directory $label_font_directory $input_font_directory
    $bg_color_success $bg_color_error $bg_color_warning $bg_color_info $bg_color_question $label_font_alert
    $modern_button_bg $modern_button_fg $modern_button_active_bg $modern_button_active_fg $modern_button_font
    $next_button_bg $next_button_fg $next_button_active_bg $next_button_active_fg $next_button_font
    $corteza_marron $hoja_verde $wood_beige $dark_moss $pine_green $forest_shadow $amarillo_savia $rojo_otoño $twilight_grey $soil_black
    $mib_selection_bg $mib_selection_fg $mib_selection_button_bg $mib_selection_button_fg
    $mib_selection_button_active_bg $mib_selection_button_active_fg $mib_selection_button_font
    $mib_selection_label_font $mib_selection_checkbutton_font
    $table_bg $table_fg $table_header_bg $table_header_fg $table_row_bg $table_row_alt_bg $table_font $table_header_font
);

1;  # Finalizar el módulo con un valor verdadero