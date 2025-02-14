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
    'PAR::Packer'
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

print "All modules are validated and patched if necessary.\n";