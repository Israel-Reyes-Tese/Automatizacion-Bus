package ABR::llenaComun;
# Version=1.0
use POSIX qw(strftime);
use warnings;
use strict;

sub new {

        my $class=shift;
        my $self;
        my $mensaje_x733;

        $self = bless( {  mensaje_x733 => \$mensaje_x733 }, $class );
}

sub vacia_mensaje_x733 {

        my $self = shift;
        my $mensaje_x733 = $self -> { mensaje_x733 };
        $$mensaje_x733 = "";
}

sub llenaEN {
        my $self    = shift;
        my $en_list = shift;
        #     my %mo_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $en_list\n";
        $en_list .= "#\$%";
        $$mensaje_x733 .= $en_list;
}

sub llenaMO {
        my $self    = shift;
        my $mo_list = shift;
        #     my %mo_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $mo_list\n";
        $mo_list .= "#\$%";
        $$mensaje_x733 .= $mo_list;
}

sub llenaPC {
        my $self    = shift;
        my $pc_list = shift;
        #     my %pc_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $pc_list\n";
        $pc_list .= "#\$%";
        $$mensaje_x733 .= $pc_list;
}

sub llenaSP {
        my $self    = shift;
        my $ps_list = shift;
        #     my %ps_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $ps_list\n";
        $ps_list .= "#\$%";
        $$mensaje_x733 .= $ps_list;
}

sub llenaPS {
        my $self    = shift;
        my $ps_list = shift;
        #     my %ps_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $ps_list\n";
        $ps_list .= "#\$%";
        $$mensaje_x733 .= $ps_list;
}

sub llenaBUS {
        my $self     = shift;
        my $bus_list = shift;
        #     my %bus_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $bus_list\n";
        $bus_list .= "#\$%";
        $$mensaje_x733 .= $bus_list;
}

sub llenaBAO {
        my $self     = shift;
        my $bao_list = shift;
        #     my %bao_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $bao_list\n";
        $bao_list .= "#\$%";
        $$mensaje_x733 .= $bao_list;
}

sub llenaTrendI {
        my $self        = shift;
        my $trendi_list = shift;
        #     my %trendi_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $trendi_list\n";
        $trendi_list   .= "#\$%";
        $$mensaje_x733 .= $trendi_list;
}

sub llenaThresholdI {
        my $self            = shift;
        my $thresholdi_list = shift;
        #   smy %thresholdi_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $thresholdi_list\n";
        $thresholdi_list .= "#\$%";
        $$mensaje_x733   .= $thresholdi_list;
}

sub llenaNI {
        my $self    = shift;
        my $ni_list = shift;
        #     my %ni_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $ni_list\n";
        $ni_list .= "#\$%";
        $$mensaje_x733 .= $ni_list;
}

sub llenaCN {
        my $self    = shift;
        my $cn_list = shift;
        #     my %cn_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $cn_list\n";
        $cn_list .= "#\$%";
        $$mensaje_x733 .= $cn_list;
}

sub llenaSCD {
        my $self     = shift;
        my $scd_list = shift;
        #     my %scd_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $scd_list\n";
        $scd_list .= "#\$%";
        $$mensaje_x733 .= $scd_list;
}

sub llenaMA {
        my $self    = shift;
        my $ma_list = shift;
        #     my %ma_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $ma_list\n";
        $ma_list .= "#\$%";
        $$mensaje_x733 .= $ma_list;
}

sub llenaPRA {
        my $self     = shift;
        my $pra_list = shift;
        #     my %pra_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $pra_list\n";
        $pra_list .= "#\$%";
        $$mensaje_x733 .= $pra_list;
}

sub llenaAT {
        my $self    = shift;
        my $at_list = shift;
        #     my %at_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $at_list\n";
        $at_list .= "#\$%";
        $$mensaje_x733 .= $at_list;
}

sub llenaAI {
        my $self    = shift;
        my $ai_list = shift;
        #     my %ai_hash;
        my $mensaje_x733 = $self->{mensaje_x733};
        #     print "EL VALOR DE MO_LIST ES: $ai_list\n";
        $ai_list .= "#\$%";
        $$mensaje_x733 .= $ai_list;
}

sub EventTime {
        my $self         = shift;
        my $et_list      = shift;
        my $mensaje_x733 = $self->{mensaje_x733};
        $et_list .= "#\$%";
        $$mensaje_x733 .= $et_list;
}

sub EventType {
        my $self         = shift;
        my $ety_list     = shift;
        my $mensaje_x733 = $self->{mensaje_x733};
        $$mensaje_x733 .= $ety_list;
}

sub fecha {
  my $self         = shift;
  my $datestring = strftime "%b %e %H:%M:%S %Z %Y", localtime;
  return $datestring;
}

1;
