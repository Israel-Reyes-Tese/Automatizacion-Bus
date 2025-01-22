package ABR::llenaComun;
# Version=1.0
use POSIX qw(strftime);
use warnings;
use strict;

sub new {
    my $class = shift;
    my $mensaje_x733;
    return bless { mensaje_x733 => \$mensaje_x733 }, $class;
}

sub vacia_mensaje_x733 {
    my $self = shift;
    ${$self->{mensaje_x733}} = "";
}

sub llenaEN {
    my ($self, $en_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$en_list#$%";
}

sub llenaMO {
    my ($self, $mo_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$mo_list#$%";
}

sub llenaPC {
    my ($self, $pc_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$pc_list#$%";
}

sub llenaSP {
    my ($self, $ps_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$ps_list#$%";
}

sub llenaPS {
    my ($self, $ps_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$ps_list#$%";
}

sub llenaBUS {
    my ($self, $bus_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$bus_list#$%";
}

sub llenaBAO {
    my ($self, $bao_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$bao_list#$%";
}

sub llenaTrendI {
    my ($self, $trendi_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$trendi_list#$%";
}

sub llenaThresholdI {
    my ($self, $thresholdi_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$thresholdi_list#$%";
}

sub llenaNI {
    my ($self, $ni_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$ni_list#$%";
}

sub llenaCN {
    my ($self, $cn_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$cn_list#$%";
}

sub llenaSCD {
    my ($self, $scd_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$scd_list#$%";
}

sub llenaMA {
    my ($self, $ma_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$ma_list#$%";
}

sub llenaPRA {
    my ($self, $pra_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$pra_list#$%";
}

sub llenaAT {
    my ($self, $at_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$at_list#$%";
}

sub llenaAI {
    my ($self, $ai_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$ai_list#$%";
}

sub EventTime {
    my ($self, $et_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= "$et_list#$%";
}

sub EventType {
    my ($self, $ety_list) = MainWindow=HASH(0x2ac8f3a3f70) agente_snmp herramientas\Archivos_temporales\Agentes_temporales\agente_snmp\ABR;
    ${$self->{mensaje_x733}} .= $ety_list;
}

sub fecha {
    return strftime "%b %e %H:%M:%S %Z %Y", localtime;
}

1;
