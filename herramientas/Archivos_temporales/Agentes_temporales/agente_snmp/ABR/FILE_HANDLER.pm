package ABR::FILE_HANDLER;
# Version=1.0
use warnings;
use strict;

sub new {

    my $class = shift;
    my $args = { @_};
    my %args_hash = %{$args};
    my $gluster_dir;
    my $auxiliary_dir;

    for(keys(%args_hash)) {

        if($_ eq "gluster_dir")
        {
            $gluster_dir = $args_hash{$_};
        }
        if($_ eq "auxiliary_dir")
        {
            $auxiliary_dir = $args_hash{$_};
        }
    }

    return bless( { gluster_dir => $gluster_dir, auxiliary_dir => $auxiliary_dir, not_send => [ ] }, $class );
}

sub write_file {

    my $self = shift;
    my $file_name = shift;
    my $file_content = shift;
    my $gluster_dir = $self -> {gluster_dir};
    my $auxiliary_dir = $self -> {auxiliary_dir};
    my $ref_files_not_send = $self -> {not_send};
    my @files_not_send = @{$ref_files_not_send};
    my $file_path;
    my $emergency_path;
    my $regreso;
    my $size;

    $file_path = $gluster_dir . "/" . $file_name;
    $emergency_path = $auxiliary_dir . "/" . $file_name;

    $regreso = open ARCH, ">", $file_path;

    if(!defined($regreso)) {

        print "I could not write to gluster directory\n";
        $regreso = open EMERGENCY, ">", $emergency_path;
        if(!defined($regreso)) {

            die "The emergency directory does not exist or is not accesible";
        }

        print EMERGENCY $file_content;
        close EMERGENCY;
        $size = scalar(@files_not_send);
        print "EL TAMAN\xD1O ES: $size\n";

        for(my $i = 0; $i < $size; $i++) {

            print "LOS ARCHIVOS DENTRO DEL ARREGLO ANTES SON: " . $files_not_send[$i] . "\n";
        }

        print "EL ARCHIVO QUE SE VA A EMPUJAR ES: " . $file_name . "\n";
        $ref_files_not_send -> [$size] =  $file_name;
        $size = scalar(@{$ref_files_not_send});
        print "EL TAMAN\xD1O ES: $size\n";

        for(my $i = 0; $i < $size; $i++) {

            print "LOS ARCHIVOS DENTRO DEL ARREGLO DESPUES SON: " . $ref_files_not_send -> [$i] . "\n";
        }

        return "EMERGENCY";
    }

    if(scalar(@files_not_send) > 0)
    {
        $self -> file_resynch();
    }

    print ARCH $file_content;
    close ARCH;
    return "WRITTEN";
}

sub file_resynch {

    my $self = shift;
    my $gluster_dir = $self -> {gluster_dir};
    my $auxiliary_dir = $self -> {auxiliary_dir};
    my $ref_files_not_send = $self -> {not_send};
    my @files_not_send = @{$ref_files_not_send};
    my $file_path;
    my $emergency_path;
    my $regreso;
    my $size;

    if(($size = scalar(@files_not_send)) > 0) {

        print "VOY A HACER RESYNCH\n";
        print "Size of the array is: " . $size . "\n";

        while (@{$ref_files_not_send}) {

            my $emergency_file = shift(@{$ref_files_not_send});
            print "The emergency file is " . $emergency_file . "\n";

            $file_path = $gluster_dir . "/" . $emergency_file;
            print "The file path is: $file_path\n";

            $emergency_path = $auxiliary_dir . "/" . $emergency_file;
            print "The emergency file path is: $emergency_path\n";

            $regreso = `mv -f $emergency_path $file_path`;
            print "EL VALOR DE REGRESO ES: " . $? . "\n";

            if($? == -1) {

                unshift(@{$ref_files_not_send}, $emergency_file);
                last;
            }
        }
    }
}

sub dummy_write {

    my $self = shift;
    my $gluster_dir = $self -> {gluster_dir};
    my $ref_files_not_send = $self -> {not_send};
    my @files_not_send = @{$ref_files_not_send};

    if(scalar(@files_not_send) > 0){

        if(opendir(DIR, $gluster_dir)) {

            print "DUMMY: IT OPENEND THE DIR\n";
            close DIR;
            $self -> file_resynch();
        }
    }
}

sub startup_write {

    my $self = shift;
    my $gluster_dir = $self -> {gluster_dir};
    my $auxiliary_dir = $self -> {auxiliary_dir};
    my $ref_files_not_send = $self -> {not_send};
    my $regreso;
    my @files;
    my $count = 0;

    if(opendir(DIR, $gluster_dir)) {

        close DIR;
        $regreso = `ls -rt $auxiliary_dir`;

        if($? == -1) {

            die "There is a problem reading files from the emergency file path";
        }

        @files = split("\n", $regreso);

        foreach(@files) {

            $ref_files_not_send -> [$count] = $_;
            $count++;
        }

        $self -> file_resynch();
    }
}

1;
