import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:x509b/src/util.dart';

import 'x509_base.dart';

class CertificateRevocationList {
  final TbsCertificateList tbsCertificateList;
  final AlgorithmIdentifier signatureAlgorithm;
  final List<int>? signatureValue;

  CertificateRevocationList(
      this.tbsCertificateList, this.signatureAlgorithm, this.signatureValue);

  ///Generate a Certificate Revocation List from its ASN1 encoding.
  ///
  /// ASN1-Definition (RFC 5280):
  ///
  ///CertificateList  ::=  SEQUENCE  {
  ///     tbsCertList          TBSCertList,
  ///     signatureAlgorithm   AlgorithmIdentifier,
  ///     signatureValue       BIT STRING  }
  factory CertificateRevocationList.fromAsn1(ASN1Sequence sequence) {
    final algorithm =
        AlgorithmIdentifier.fromAsn1(sequence.elements[1] as ASN1Sequence);
    return CertificateRevocationList(
        TbsCertificateList.fromAsn1(sequence.elements[0] as ASN1Sequence),
        algorithm,
        toDart(sequence.elements[2]));
  }

  ASN1Sequence toAsn1() {
    return ASN1Sequence()
      ..add(tbsCertificateList.toAsn1())
      ..add(signatureAlgorithm.toAsn1())
      ..add(fromDart(signatureValue));
  }
}

class TbsCertificateList {
  final int version;
  final AlgorithmIdentifier signatureAlgorithm;
  final Name issuer;
  final DateTime thisUpdate;
  final DateTime nextUpdate;
  final Map<BigInt, RevokedCertificate>? revokedCertificates;
  final List<Extension>? crlExtensions;
  final Uint8List? encodedBytes;

  TbsCertificateList(
      {this.version = 1,
      required this.signatureAlgorithm,
      required this.issuer,
      required this.thisUpdate,
      required this.nextUpdate,
      this.revokedCertificates,
      this.crlExtensions,
      this.encodedBytes});

  factory TbsCertificateList.fromAsn1(ASN1Sequence sequence) {
    var ex = <Extension>[];
    var certs = <BigInt, RevokedCertificate>{};
    if (sequence.elements.length >= 6) {
      //There are extensions or revoked certs
      var element = sequence.elements[5];
      if (element.tag == 0xa0) {
        //extensions
        ex = (ASN1Parser(element.contentBytes()).nextObject() as ASN1Sequence)
            .elements
            .map((v) => Extension.fromAsn1(v as ASN1Sequence))
            .toList();
      } else {
        //revoked certs
        var tmp = (element as ASN1Sequence)
            .elements
            .map((v) => RevokedCertificate.fromAsn1(v as ASN1Sequence));
        certs = {for (var item in tmp) item.userCertificate: item};
        if (sequence.elements.length == 7) {
          var element2 = sequence.elements[6];
          ex = (ASN1Parser(element2.contentBytes()).nextObject()
                  as ASN1Sequence)
              .elements
              .map((v) => Extension.fromAsn1(v as ASN1Sequence))
              .toList();
        }
      }
    }
    return TbsCertificateList(
        version: toDart(sequence.elements[0]).toInt(),
        signatureAlgorithm:
            AlgorithmIdentifier.fromAsn1(sequence.elements[1] as ASN1Sequence),
        issuer: Name.fromAsn1(sequence.elements[2] as ASN1Sequence),
        thisUpdate: toDart(sequence.elements[3]),
        nextUpdate: toDart(sequence.elements[4]),
        revokedCertificates: certs.isNotEmpty ? certs : null,
        crlExtensions: ex.isNotEmpty ? ex : null,
        encodedBytes: sequence.encodedBytes);
  }

  ASN1Sequence toAsn1() {
    var seq = ASN1Sequence();
    seq.add(fromDart(version));
    seq.add(signatureAlgorithm.toAsn1());
    seq.add(issuer.toAsn1());
    seq.add(fromDart(thisUpdate));
    seq.add(fromDart(nextUpdate));
    if (revokedCertificates != null && revokedCertificates!.isNotEmpty) {
      var certSeq = ASN1Sequence();
      for (var entry in revokedCertificates!.values) {
        certSeq.add(entry.toAsn1());
      }
      seq.add(certSeq);
    }
    if (crlExtensions != null && crlExtensions!.isNotEmpty) {
      var extSeq = ASN1Sequence();
      for (var entry in crlExtensions!) {
        extSeq.add(entry.toAsn1());
      }
      seq.add(ASN1Object.preEncoded(0xa0, extSeq.encodedBytes));
    }
    return seq;
  }
}

class RevokedCertificate {
  final BigInt userCertificate;
  final DateTime revocationDate;
  final List<Extension>? crlEntryExtensions;

  RevokedCertificate(this.userCertificate, this.revocationDate,
      [this.crlEntryExtensions]);

  factory RevokedCertificate.fromAsn1(ASN1Sequence sequence) {
    //TODO handle Extensions
    return RevokedCertificate(
        toDart(sequence.elements[0]), toDart(sequence.elements[1]));
  }

  ASN1Sequence toAsn1() {
    var seq = ASN1Sequence();
    seq.add(fromDart(userCertificate));
    seq.add(fromDart(revocationDate));
    //TODO handle Extensions
    return seq;
  }
}
