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

# Estilo de fuente para las etiquetas
our $label_font = ['Verdana', 24, 'bold'];

# Estilo de fuente para los botones
our $button_font = ['Verdana', 16, 'bold'];

# Estilo de fuente para los botones de la barra de herramientas
our $toolbar_button_font = ['Verdana', 12, 'bold'];

# Estilo de fuente para los botones de agentes
our $agents_button_font = ['Verdana', 16, 'bold'];

# Export all variables
our @EXPORT_OK = qw($bg_color $fg_color $button_color $label_font $button_font $toolbar_button_font $agents_button_font);

1;  # Finalizar el módulo con un valor verdadero