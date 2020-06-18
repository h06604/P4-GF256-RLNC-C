/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<48> decodeswitch = 0x000000022200;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_NC = 0x90;
const bit<8>  TYPE_TCP = 0x06;
#define allencodingnumber 2
#define payloadsize 8
#define allpktsize 184 /*176(16(do not encoding)+160)+11648(payloadsize1456*8)*/
#define PKTNUMBER 2
#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_RESUBMIT 6
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<128> other;
}

header NC_t{
    bit<4>  primitive;
    bit<12> label;
    bit<8>  coeff1;
    bit<8>  coeff2;
}


header payload_t{
    bit<payloadsize>    input;
}

struct metadata {
    bit<32> packet_length;
    bit<32> packet_length_original;
    bit<2>  encodingstatus;
    bit<1>  decodingstatus;
    bit<1>  encodingOK;
    bit<1>  decodingOK;
    bit<8>  enflowID;/*編碼當前處理第幾個flow*/
    bit<8>  deflowID;/*解碼當前處理第幾個flow*/
    bit<12> debatch_now;/*當前處理第幾個批次 因為NC label最後會設為無效 DLNC無法使用*/

}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    NC_t         NC;
    tcp_t        tcp;
    payload_t    payload;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.instance_type){
            PKT_INSTANCE_TYPE_NORMAL : parse_packetsize_fisttime;
            PKT_INSTANCE_TYPE_RESUBMIT : parse_packetsize;
        }
    }

    state parse_packetsize_fisttime{
        meta.packet_length = standard_metadata.packet_length;
        meta.packet_length_original = standard_metadata.packet_length;
        transition parse_ethernet;
    }

    state parse_packetsize{
        meta.packet_length = meta.packet_length_original;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        meta.packet_length = meta.packet_length - 14;
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.packet_length = meta.packet_length - 20;
        transition select(hdr.ipv4.protocol) {
            TYPE_NC : parse_NC;          
            TYPE_TCP : parse_tcp;
            default: accept; 
        }
    }
    state parse_NC{
        packet.extract(hdr.NC);
        meta.packet_length = meta.packet_length - 4;
        transition parse_tcp;
    }

    state parse_tcp{
        packet.extract(hdr.tcp);
        meta.packet_length = meta.packet_length - 20;
        transition parse_payload;
    }

    state parse_payload{
        packet.extract(hdr.payload);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {


    register<bit<10>>(256) antilog_buffer;
    register<bit<8>>(1025) log_buffer;
    register<bit<allpktsize>>(1000) codingbuffer0;
    register<bit<allpktsize>>(1000) codingbuffer1;
    register<bit<4>>(1000) batch_number;
    register<bit<32>>(2) storecounter;
    register<bit<32>>(1) codingcounter;


    bit<8>  combinetmp0;
    bit<8>  combinetmp1;
    bit<8>  addtmp;
    bit<8>  multitmp;
    bit<8>  divtmp;

    bit<32> storecountertmp;
    bit<32> codingcountertmp;
    bit<allpktsize> buffertmp0;
    bit<allpktsize> buffertmp1;
    bit<32> checktmp0;
    bit<32> checktmp1;
    bit<1>  dropflag = 0;
    bit<4>  batchtmp = 0;

    action noaction_prim(){
        hdr.NC.primitive = 4w0;
    }

    action encoding_prim(bit<8> flowID){
        hdr.NC.primitive = 4w2;
        meta.enflowID = flowID;
    }

    action decoding_prim(){
        hdr.NC.primitive = 4w3;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }
    action GF_addition(bit<8> a, bit<8> b){
        addtmp = a ^ b;
    }
    action GF_division(bit<8> e,bit<8> f){
        bit<10>  divreadtmp0;
        bit<10>  divreadtmp1;
        antilog_buffer.read(divreadtmp0,(bit<32>)e);
        antilog_buffer.read(divreadtmp1,(bit<32>)f);
        
        divreadtmp0 = divreadtmp0 + 255;
        log_buffer.read(divtmp, (bit<32>)divreadtmp0 - (bit<32>)divreadtmp1);
        
    }

    action GF_multiplication(bit<8> c,bit<8> d){
        bit<10>  mulreadtmp0;
        bit<10>  mulreadtmp1;
        antilog_buffer.read(mulreadtmp0,(bit<32>)c);
        antilog_buffer.read(mulreadtmp1,(bit<32>)d);
        log_buffer.read(multitmp,(bit<32>)mulreadtmp0 + (bit<32>)mulreadtmp1);

    }

    action coeffgenerator(){
        random(hdr.NC.coeff1,1,255);
        random(hdr.NC.coeff2,1,255);
    }

    action enstoreflow0(){
        storecounter.read(storecountertmp,0);
        if(storecountertmp == 1000){
            storecountertmp = 0;
        }
        codingbuffer0.write(storecountertmp,hdr.NC.coeff1++hdr.NC.coeff2++
        hdr.tcp.srcPort++hdr.tcp.dstPort++hdr.tcp.other++hdr.payload.input);
        storecountertmp = storecountertmp + 1;
        storecounter.write(0,storecountertmp);
    }

    action enstoreflow1(){
        storecounter.read(storecountertmp,1);
        if(storecountertmp == 1000){
            storecountertmp = 0;
        }
        codingbuffer1.write(storecountertmp,hdr.NC.coeff1++hdr.NC.coeff2++
        hdr.tcp.srcPort++hdr.tcp.dstPort++hdr.tcp.other++hdr.payload.input);
        storecountertmp = storecountertmp + 1;
        storecounter.write(1,storecountertmp); 
    }

    action destoreflow0(){
        codingbuffer0.write((bit<32>)hdr.NC.label,hdr.NC.coeff1++hdr.NC.coeff2++
        hdr.tcp.srcPort++hdr.tcp.dstPort++hdr.tcp.other++hdr.payload.input);
        batchtmp = batchtmp + 1;
        batch_number.write((bit<32>)hdr.NC.label,batchtmp);

    }

    action destoreflow1(){
        codingbuffer1.write((bit<32>)hdr.NC.label,hdr.NC.coeff1++hdr.NC.coeff2++
        hdr.tcp.srcPort++hdr.tcp.dstPort++hdr.tcp.other++hdr.payload.input);
        batchtmp = batchtmp + 1;
        batch_number.write((bit<32>)hdr.NC.label,batchtmp);
    }
/*
    action linearcombine(inout bit<8> z,bit<8> x,bit<8> y){
        GF_multiplication(hdr.NC.coeff1,x);
        combinetmp0 = multitmp;
        GF_multiplication(hdr.NC.coeff2,y);
        combinetmp1 = multitmp;
        GF_addition(combinetmp0,combinetmp1);
        z = addtmp;
    }

    action encodeall(inout bit<allpktsize> b0,inout bit<allpktsize> b1,inout bit<allpktsize> pz){
        b0 = b0 << 16;b1 = b1 << 16;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;     
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
        b0 = b0 << 8;b1 = b1 << 8;pz = pz << 8;
        linearcombine(pz[7:0],b0[allpktsize-1:allpktsize-8],b1[allpktsize-1:allpktsize-8]);
    }
*/

    action gaussian(inout bit<8> p0,inout bit<8> p1,bit<8> y1,bit<8> y2,bit<8> a1,bit<8> b1,bit<8> a2,bit<8> b2){
        bit<8> B2 = b2;
        bit<8> Y2 = y2;/*這些參數運算過程會替換 但不想改變原數值*/

        GF_division(a2,a1);
        /*
        GF_multiplication(divtmp,a1);
        GF_addition(multitmp,a2);
        a2 = addtmp;
        */ 
        GF_multiplication(divtmp,b1);
        GF_addition(multitmp,B2);
        B2 = addtmp;
        GF_multiplication(divtmp,y1);
        GF_addition(multitmp,Y2);
        Y2 = addtmp;

        GF_division(Y2,B2);
        p1 = divtmp;
        GF_multiplication(divtmp,b1);
        GF_addition(multitmp,y1);

        GF_division(addtmp,a1);
        p0 = divtmp;

    }

    action decodeall(inout bit<allpktsize> db0,inout bit<allpktsize> db1){
        bit<8>  db0coe0 = db0[allpktsize-1:allpktsize-8];
        bit<8>  db0coe1 = db0[allpktsize-9:allpktsize-16];
        bit<8>  db1coe0 = db1[allpktsize-1:allpktsize-8];
        bit<8>  db1coe1 = db1[allpktsize-9:allpktsize-16];
        db0 = db0 << 16;db1 = db1 << 16;/*coeff do not encoding*/
        bit<allpktsize> ans0 = 0;
        bit<allpktsize> ans1 = 0;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);
        db0 = db0 << 8;db1 = db1 << 8;ans0 = ans0 << 8;ans1 = ans1 << 8;
        gaussian(ans0[7:0],ans1[7:0],db0[allpktsize-1:allpktsize-8],db1[allpktsize-1:allpktsize-8],db0coe0,db0coe1,db1coe0,db1coe1);

        codingbuffer0.write((bit<32>)meta.debatch_now,ans0);
        codingbuffer1.write((bit<32>)meta.debatch_now,ans1);
    }

    action pktrecovery(bit<allpktsize> pktinfo){
        hdr.tcp.srcPort = pktinfo[allpktsize-17:allpktsize-32];
        hdr.tcp.dstPort = pktinfo[allpktsize-33:allpktsize-48];     
        hdr.tcp.other = pktinfo[allpktsize-49:allpktsize-176];
        hdr.payload.input = pktinfo[allpktsize-177:0];
    }


    action DLNC1(){
        codingbuffer0.read(buffertmp0,(bit<32>)meta.debatch_now);
        codingbuffer1.read(buffertmp1,(bit<32>)meta.debatch_now);
        decodeall(buffertmp0,buffertmp1);
        codingbuffer0.read(buffertmp0,(bit<32>)meta.debatch_now);
        pktrecovery(buffertmp0);
        meta.decodingstatus=1;
        clone3(CloneType.E2E, 350, {standard_metadata , meta});
    }

    action DLNC2(){ 
        codingbuffer1.read(buffertmp1,(bit<32>)meta.debatch_now);
        pktrecovery(buffertmp1);
        batchtmp = 0;
        batch_number.write((bit<32>)meta.debatch_now,batchtmp);
    }
/*
    action commonLNC(){
        bit<allpktsize> commontmp = 0;
        coeffgenerator();
        codingcounter.read(codingcountertmp,0);
        codingbuffer0.read(buffertmp0,(bit<32>)codingcountertmp);
        codingbuffer1.read(buffertmp1,(bit<32>)codingcountertmp);
        encodeall(buffertmp0,buffertmp1,commontmp);
        pktrecovery(commontmp);     
        hdr.NC.label =  (bit<12>)codingcountertmp;
        meta.encodingstatus = meta.encodingstatus + 1;
    }
*/
    action LNC1(){
        bit<allpktsize> LNC1tmp = 0;
        coeffgenerator();
        codingcounter.read(codingcountertmp,0);
        codingbuffer0.read(LNC1tmp,(bit<32>)codingcountertmp);
        pktrecovery(LNC1tmp);     
        hdr.NC.label =  (bit<12>)codingcountertmp;
        meta.encodingstatus = meta.encodingstatus + 1;    
        clone3(CloneType.E2E, 250, {standard_metadata , meta});
    }

    action LNC2(){
        //commonLNC();
        clone3(CloneType.E2E, 251, {standard_metadata , meta});

    }

    action LNC_last(){
        bit<allpktsize> LNC2tmp = 0;
        coeffgenerator();
        codingcounter.read(codingcountertmp,0);
        codingbuffer1.read(LNC2tmp,(bit<32>)codingcountertmp);
        pktrecovery(LNC2tmp);     
        hdr.NC.label =  (bit<12>)codingcountertmp;
        meta.encodingstatus = meta.encodingstatus + 1;
        /*最後一個LNC需要計數已編碼數量*/
        codingcountertmp = codingcountertmp + 1;
        if(codingcountertmp == 1000){
            codingcountertmp = 0;
        }
        codingcounter.write(0,codingcountertmp);
    }

    action decodingcheck(){ 
        if(batchtmp == 2){
            meta.decodingOK = 1;
        }
    }

    action encodingcheck(){
        codingcounter.read(codingcountertmp,0);
        storecounter.read(checktmp0,0);
        storecounter.read(checktmp1,1);
        if(codingcountertmp < checktmp0 && codingcountertmp < checktmp1){
            meta.encodingOK = 1;
        }
    }

    action remove_NC(){
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 4;
        hdr.NC.setInvalid();
        hdr.ipv4.protocol = 0x06;
    }

    action check_batch(){
        batch_number.read(batchtmp,(bit<32>)hdr.NC.label);

        if(batchtmp == 0){
            meta.deflowID = 0;
        }
        else if(batchtmp == 1){
            meta.deflowID = 1;
        }
        else{
            dropflag = 1;
        }
    }

    table remove_header {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            remove_NC;
        }
        const entries = {
            decodeswitch: remove_NC();
        }
    }

    table enstore_packet{
        key = {
            meta.enflowID: exact;
        }
        actions = {
            enstoreflow0;
            enstoreflow1;
        }
        const entries = {
            0: enstoreflow0();
            1: enstoreflow1();
        }
    }

    table destore_packet{
        key = {
            meta.deflowID: exact;
        }
        actions = {
            destoreflow0;
            destoreflow1;
        }
        const entries = {
            0: destoreflow0();
            1: destoreflow1();
        }
    }

    table NC_init{
        key = {
            hdr.ipv4.srcAddr: lpm;
            hdr.tcp.dstPort: exact;
        }
        actions = {
            encoding_prim;
        }
        const entries = {
            (0xc0a83805,1234) : encoding_prim(0);
            (0xc0a83805,1235) : encoding_prim(1);
        }
    }

    table LNCgenerator{
        key = {
            meta.encodingstatus: exact;
        }
        actions = {
            LNC1;
            LNC2;
            LNC_last;
        }
        const entries = {
            0: LNC1();
            allencodingnumber-1: LNC_last();
        }       
    }

    table LNCdecoder{
        key = {
            meta.decodingstatus: exact;
        }
        actions = {
            DLNC1;
            DLNC2;
        }
        const entries = {
            0: DLNC1();
            1: DLNC2();
        }
    }

    table modifyNCaction {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            decoding_prim;
            noaction_prim;
        }
        const entries = {
            decodeswitch: decoding_prim();
        }
        default_action = noaction_prim;
    }    
            
    apply {
            if(hdr.payload.isValid() || hdr.NC.isValid()){
                if(hdr.NC.isValid() == false){
                    hdr.NC.setValid();
                    hdr.ipv4.protocol = 0x90;
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
                    NC_init.apply();
                }
                
                if(meta.encodingstatus == 0 && meta.decodingstatus == 0){
                    if(hdr.NC.primitive == 2){
                        enstore_packet.apply();
                        encodingcheck();
                    }
                    else if(hdr.NC.primitive == 3){
                        check_batch();
                        if(dropflag == 1){
                            drop();
                        }
                        else{
                            destore_packet.apply();
                            decodingcheck();
                            meta.debatch_now = hdr.NC.label;
                        }
                    }               
                }
                if(meta.encodingOK == 1){
                    LNCgenerator.apply();
                }
                else if(meta.decodingOK == 1){
                    LNCdecoder.apply();
                }
                else{
                    if(hdr.NC.primitive != 0){
                        drop();
                    }
                }               
          
                modifyNCaction.apply();
                remove_header.apply();         
            }
     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.NC);
        packet.emit(hdr.tcp);
        packet.emit(hdr.payload);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
