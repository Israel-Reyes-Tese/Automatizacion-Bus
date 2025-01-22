package ABR::FILE_HANDLER;
use warnings;
use strict;

sub new {
    my $class = shift;
    my $args = { @_ };
    my $gluster_dir = $args->{gluster_dir};
    my $auxiliary_dir = $args->{auxiliary_dir};

    return bless { gluster_dir => $gluster_dir, auxiliary_dir => $auxiliary_dir, not_send => [] }, $class;
}

sub write_file {
    my ($self, $file_name, $file_content) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    my $file_path = "$self->{gluster_dir}/$file_name";
    my $emergency_path = "$self->{auxiliary_dir}/$file_name";

    unless (open my $fh, '>', $file_path) {
        unless (open my $em_fh, '>', $emergency_path) {
            die "The emergency directory does not exist or is not accessible";
        }
        print $em_fh $file_content;
        close $em_fh;
        push @{$self->{not_send}}, $file_name;
        return "EMERGENCY";
    }

    $self->file_resynch if @{$self->{not_send}};
    print $fh $file_content;
    close $fh;
    return "WRITTEN";
}

sub file_resynch {
    my $self = shift;
    while (my $emergency_file = shift @{$self->{not_send}}) {
        my $file_path = "$self->{gluster_dir}/$emergency_file";
        my $emergency_path = "$self->{auxiliary_dir}/$emergency_file";
        unless (system("mv -f $emergency_path $file_path") == 0) {
            unshift @{$self->{not_send}}, $emergency_file;
            last;
        }
    }
}

sub dummy_write {
    my $self = shift;
    $self->file_resynch if @{$self->{not_send}} && opendir my $dir, $self->{gluster_dir};
}

sub startup_write {
    my $self = shift;
    if (opendir my $dir, $self->{gluster_dir}) {
        my $regreso = `ls -rt $self->{auxiliary_dir}`;
        die "There is a problem reading files from the emergency file path" if $? == -1;
        @{$self->{not_send}} = split "\n", $regreso;
        $self->file_resynch;
    }
}

1;
