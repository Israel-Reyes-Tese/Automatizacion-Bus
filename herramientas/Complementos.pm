# herramientas/Complementos.pm
package herramientas::Complementos;
# Importar módulos
use strict;
use warnings;
use Tk;

use FindBin;  # Añadir FindBin para obtener la ruta del script
use lib $FindBin::Bin . "/herramientas";  # Añadir la carpeta donde se encuentran los módulos

# Importar los estilos
use Estilos;
# Dentro de la misma ventana principal

# Función para crear una label con un texto

sub create_label {
    my ($main_window, $text, $posicion) = @_;

    if ($posicion eq 'Titulo-Principal'){
        $main_window->Label(
            -text => $text, 
            -font => $herramientas::Estilos::label_font,
            -bg => $herramientas::Estilos::bg_color,
            -fg => $herramientas::Estilos::fg_color
            )->pack(-pady => 20);     
    } 

}







# Ventas extras - emergentes
# Función para mostrar información "Acerca de"
sub show_about {
    my ($main_window) = @_;
    my $about_window = $main_window->Toplevel();
    $about_window->title("Acerca de");
    $about_window->Label(-text => "AutoManage GUI\nVersión 1.0\nDesarrollado en Perl", -font => $Estilo::label_font)->pack(padx => 20, pady => 20);
    $about_window->Button(-text => 'Cerrar', -command => sub { $about_window->destroy() })->pack(pady => 10);
}



1;  # Finalizar el módulo con un valor verdadero