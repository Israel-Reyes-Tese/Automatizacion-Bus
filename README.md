# Automatizacion-Bus
Scripts automatizacion de los procesos de los que se ejecutan en los buses




# Notas de instalacion de dependencias y errores conocidos
# Librerias instaladas
- perl -MTk -MData::Dumper -e "print Dumper(\%INC)" 
- perl -MTk::FileDialog -MData::Dumper -e "print Dumper(\%INC)"
# Validar una sola 
- perl -MTk -MData::Dumper -e "print Dumper(\$Tk::VERSION)"

- cpanm
Tk.pm
# cpanm Tk
- CPAN shell
## perl -MCPAN -e shell
## install Tk

# cpan Tk

-- "C:\Strawberry\perl\site\lib\Tk.pod"
-- "C:\Strawberry\perl\site\lib\Tk"
-- "C:\Strawberry\perl\site\lib\Tk.pm"

- URL
# cpanm  https://github.com/Lamprecht/perl-tk.git@Strawberry-5.38-patch 


Tk/FileDialog.pm
# cpanm Tk::FileDialog

# Edit C:/Strawberry/perl/site/lib/Tk/FileDialog.pm
Unrecognized character \x17; marked by <-- HERE after nSave) = $<-- HERE near column 22

# Funcion original:
####  PRIVATE METHODS AND SUBROUTINES ####
sub IsNum {
    my($parm) = @_;
    my($warnSave) = $;
    $ = 0;
    my($res) = (($parm + 0) eq $parm);
    $ = $warnSave;
    return $res;
}

# Reemplazo:

sub IsNum {
    my($parm) = @_;
    my($warnSave) = $^W;
    $^W = 0;
    my($res) = (($parm + 0) eq $parm);
    $^W = $warnSave;
    return $res;
}

Tk/JComboBox.pm
# cpanm Tk::JComboBox

Tk/TableMatrix.pm
# cpanm Tk::TableMatrix


Log/Log4perl.pm
# cpanm Log::Log4perl


Log::Dispatch::File
# cpanm Log::Dispatch

Proc/Background.pm
# cpanm Proc::Background



# Integracion:
PAR::Packer
#cpan install PAR::Packer



# Opcionales
Net/SNMPTrapd.pm 
# cpanm Net::SNMPTrapd

NetSNMP/agent.pm
# cpanm NetSNMP/agent.pm  ???

Digest/MurmurHash.pm 
# cpanm Digest::MurmurHash




IPC/Run.pm
# cpanm IPC::Run 
# "C:\Strawberry\perl\vendor\lib\IPC"
# "C:\Strawberry\perl\lib\IPC"

Proc/Background.pm
# cpanm Proc::Background
# "C:\Strawberry\perl\site\lib\Proc"
 


Log/Dispatch/File.pm
# cpanm Log::Dispatch
