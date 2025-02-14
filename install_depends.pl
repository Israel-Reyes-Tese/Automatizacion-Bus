use strict;
use warnings;
use File::Copy;
use Archive::Extract;
use File::Path qw(make_path remove_tree);

my @modules = (
    'Tk',
    'Tk::FileDialog',
    'Tk::JComboBox',
    'Tk::TableMatrix',
    'Log::Log4perl',
    'Log::Dispatch',
    'Proc::Background',
    'IPC::Run',
    'PAR::Packer', 
);

my %module_to_zip = (
    'Tk'             => 'Tk.zip',
    'IPC::Run'       => 'IPC.zip',
    'Log::Log4perl'  => 'Log.zip',
    'Log::Dispatch'  => 'Log.zip',
    'Proc::Background' => 'Proc.zip'
);

my $patch_dir = 'herramientas/Archivos_temporales/Parche/Librerias';
my $temp_dir = 'herramientas/Archivos_temporales/Parche/Librerias/temp';

# Primera validación de las dependencias
foreach my $module (@modules) {
    eval "use $module";
    if ($@) {
        print "Module $module is not installed. Installing...\n";
        if ($module eq 'Tk') {
            system("cpanm https://github.com/Lamprecht/perl-tk.git\@Strawberry-5.38-patch");
        } else {
            system("cpanm $module");
        }
    } else {
        no strict 'refs';
        my $version = ${"${module}::VERSION"};
        print "Module $module is installed, version: " . (defined $version ? $version : 'unknown') . "\n";
    }
}

# Segunda validación de las dependencias
foreach my $module (keys %module_to_zip) {
    eval "use $module";
    if ($@) {
        print "Module $module is not installed correctly. Extracting from zip...\n";
        my $zip_file = "$patch_dir/$module_to_zip{$module}";
        my $ae = Archive::Extract->new(archive => $zip_file);
        $ae->extract(to => $temp_dir) or die "Error extracting $zip_file: $!";

        if ($module eq 'Tk') {
            my $tk_dir = 'C:/Strawberry/perl/site/lib/Tk';
            make_path($tk_dir);
            dircopy("$temp_dir/Tk", $tk_dir) or die "Error copying Tk files: $!";
            copy("$patch_dir/Tk.pod", 'C:/Strawberry/perl/site/lib/Tk.pod') or die "Error copying Tk.pod: $!";
            copy("$patch_dir/Tk.pm", 'C:/Strawberry/perl/site/lib/Tk.pm') or die "Error copying Tk.pm: $!";
        } elsif ($module eq 'IPC::Run') {
            my $ipc_dir = 'C:/Strawberry/perl/vendor/lib/IPC';
            make_path($ipc_dir);
            dircopy("$temp_dir/IPC", $ipc_dir) or die "Error copying IPC files: $!";
        } elsif ($module eq 'Proc::Background') {
            my $proc_dir = 'C:/Strawberry/perl/site/lib/Proc';
            make_path($proc_dir);
            dircopy("$temp_dir/Proc", $proc_dir) or die "Error copying Proc files: $!";
        } else {
            my $module_dir = "C:/Strawberry/perl/site/lib/" . (split(/::/, $module))[-1];
            make_path($module_dir);
            dircopy("$temp_dir/" . (split(/::/, $module))[-1], $module_dir) or die "Error copying $module files: $!";
        }

        remove_tree($temp_dir);
    }
}

# Patch Tk::FileDialog
eval {
    require Tk::FileDialog;
    Tk::FileDialog->import();
    print "Tk::FileDialog loaded successfully.\n";

};
if ($@) {
    print "Error loading Tk::FileDialog: $@\n";
    # Aplicar parche a Tk/FileDialog.pm
    my $filedialog_path = 'C:/Strawberry/perl/site/lib/Tk/FileDialog.pm';
    if (-e $filedialog_path) {
        open my $fh, '<', $filedialog_path or die "Could not open '$filedialog_path' for reading: $!";
        my @lines = <$fh>;
        close $fh;
        
        open $fh, '>', $filedialog_path or do {
            print("No se pudo aplicar el parche automáticamente. Por favor, copie el contenido de la carpeta:\n$patch_dir\na la carpeta:\n$filedialog_path", 48, "Error");
            system("explorer $patch_dir");
            system("explorer C:/Strawberry/perl/site/lib/Tk");
            die "Could not open '$filedialog_path' for writing: $!";
        };

        my $inside_isnum = 0;
        foreach my $line (@lines) {
            if ($line =~ /^sub IsNum/) {
                print $fh "sub IsNum {\n";
                print $fh "    my(\$parm) = \@_;\n";
                print $fh "    my(\$warnSave) = \$^W;\n";
                print $fh "    \$^W = 0;\n";
                print $fh "    my(\$res) = ((\$parm + 0) eq \$parm);\n";
                print $fh "    \$^W = \$warnSave;\n";
                print $fh "    return \$res;\n";
                print $fh "}\n";
                $inside_isnum = 1;
            } elsif ($inside_isnum) {
                if ($line =~ /^\}/) {
                    $inside_isnum = 0;
                }
            } else {
                print $fh $line;
            }
        }
        close $fh;
        print "Patched 'sub IsNum' in $filedialog_path\n";
    } else {
        print "Error: $filedialog_path does not exist.\n";
    }
}

print "All modules are validated and patched if necessary.\n";