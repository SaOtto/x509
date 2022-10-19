import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:http/http.dart';
import 'package:quiver/collection.dart';

import 'certificate_revocation_list.dart';
import 'util.dart';
import 'x509_base.dart';

Future<List<X509Certificate>> buildCertificateChain(
    X509Certificate toVerify, List<X509Certificate> trustAnchor,
    [List<X509Certificate>? currentChain]) async {
  var trustAnchorAsMap = {
    for (var item in trustAnchor) item.tbsCertificate.subject.toString(): item
  };
  currentChain ??= [toVerify];
  if (!trustAnchorAsMap
      .containsKey(toVerify.tbsCertificate.issuer.toString())) {
    var extensions = toVerify.tbsCertificate.extensions;
    if (extensions != null && extensions.isNotEmpty) {
      AccessDescription caIssuers;
      try {
        var aiAccessExt = extensions.firstWhere((element) =>
            element.extnId == ObjectIdentifier([1, 3, 6, 1, 5, 5, 7, 1, 1]));
        var aiAccess = aiAccessExt.extnValue as AuthorityInformationAccess;
        caIssuers = aiAccess.descriptions.firstWhere((element) =>
            element.accessMethod ==
            ObjectIdentifier([1, 3, 6, 1, 5, 5, 7, 48, 2]));
      } catch (e) {
        throw Exception(
            'No Authority Information Access extension with caIssuers value (Certificate DN: ${toVerify.tbsCertificate.subject}). Cant generate certificate chain. $e');
      }
      if (caIssuers.accessLocation?.choice == 6) {
        var url =
            (caIssuers.accessLocation!.contents as ASN1IA5String).stringValue;
        var res = await get(Uri.parse(url));
        if (res.statusCode == 200) {
          var issuer = X509Certificate.fromAsn1(
              ASN1Parser(res.bodyBytes).nextObject() as ASN1Sequence);
          currentChain = [issuer] + currentChain;
          return await buildCertificateChain(issuer, trustAnchor, currentChain);
        } else {
          throw Exception(
              'cant fetch issuer certificate for ${toVerify.tbsCertificate.subject}');
        }
      } else {
        throw Exception('Access method is no url, but can only handle urls');
      }
    } else {
      throw Exception(
          'Missing extensions section. Cant generate Certificate chain');
    }
  } else {
    currentChain = [
          trustAnchorAsMap[toVerify.tbsCertificate.issuer.toString()]!
        ] +
        currentChain;
    return currentChain;
  }
}

/// Verifies a chain of X.509 certificates
///
/// [certificateChain] must be an ordered List, starting with a trust anchor at index 0 and ending with the certificate of interest.
Future<bool> verifyCertificateChain(List<X509Certificate> certificateChain,
    [DateTime? checkDate]) async {
  for (var i = 0; i < certificateChain.length - 1; i++) {
    var verified = await verifyCertificate(
        certificateChain[i + 1], certificateChain[i], checkDate);
    if (!verified) {
      return false;
    }
  }
  return true;
}

Future<bool> verifyCertificate(dynamic toVerify, X509Certificate issuer,
    [DateTime? checkDate]) async {
  Uint8List dataToVerify;
  if (toVerify is X509Certificate) {
    dataToVerify = toVerify.tbsCertificate.encodedBytes != null
        ? toVerify.tbsCertificate.encodedBytes!
        : toVerify.tbsCertificate.toAsn1().encodedBytes;
    await _x509Checks(toVerify, issuer, checkDate);
  } else if (toVerify is CertificateRevocationList) {
    dataToVerify = toVerify.tbsCertificateList.encodedBytes != null
        ? toVerify.tbsCertificateList.encodedBytes!
        : toVerify.tbsCertificateList.toAsn1().encodedBytes;
    _crlChecks(toVerify, issuer, checkDate);
  } else {
    throw Exception(
        'Verification of ${toVerify.runtimeType} is not supported. Only supported types are X509Certificate and CertificateRevocationList');
  }

  var signature = toVerify.signatureValue;
  if (signature == null) {
    throw Exception('Certificate is not signed');
  }

  var issuerPubKey = issuer.publicKey;
  //RSA-Signature
  if (toVerify.signatureAlgorithm.algorithm.name
      .toLowerCase()
      .contains('rsa')) {
    if (!issuerPubKey.algorithm.contains('rsa')) {
      throw Exception(
          'A ${toVerify.signatureAlgorithm.algorithm.name} signature cant be generated with a ${issuerPubKey.algorithm} key.');
    }
    var pubKey = publicKeyFromAsn1(
        Uint8List.fromList(issuer.publicKey.publicKeyDer),
        issuer.publicKey.algorithm);
    if (toVerify.signatureAlgorithm.algorithm.name ==
        'sha256WithRSAEncryption') {
      var verifier = pubKey.createVerifier(algorithms.signing.rsa.sha256);
      return verifier.verify(dataToVerify,
          Signature(Uint8List.fromList(toVerify.signatureValue!)));
    } else if (toVerify.signatureAlgorithm.algorithm.name ==
        'sha384WithRSAEncryption') {
      var verifier = pubKey.createVerifier(algorithms.signing.rsa.sha384);
      return verifier.verify(dataToVerify,
          Signature(Uint8List.fromList(toVerify.signatureValue!)));
    } else if (toVerify.signatureAlgorithm.algorithm.name ==
        'sha512WithRSAEncryption') {
      var verifier = pubKey.createVerifier(algorithms.signing.rsa.sha512);
      return verifier.verify(dataToVerify,
          Signature(Uint8List.fromList(toVerify.signatureValue!)));
    }
  } else if (toVerify.signatureAlgorithm.algorithm.name ==
      'ecdsa-with-SHA256') {
    if (!issuerPubKey.algorithm.contains('ecPublicKey')) {
      throw Exception(
          'A ${toVerify.signatureAlgorithm.algorithm.name} signature cant be generated with a ${issuerPubKey.algorithm} key.');
    }
    var pubKey = publicKeyFromAsn1(
        Uint8List.fromList(issuer.publicKey.publicKeyDer),
        issuer.publicKey.algorithm,
        issuer.publicKey.parameters);

    var verifier = pubKey.createVerifier(algorithms.signing.ecdsa.sha256);
    var parse = ASN1Parser(Uint8List.fromList(toVerify.signatureValue!));
    var sig = parse.nextObject() as ASN1Sequence;
    BigInt r = toDart(sig.elements[0]);
    BigInt s = toDart(sig.elements[1]);
    return verifier.verify(
        dataToVerify,
        Signature(
            Uint8List.fromList(bigIntToUint8List(r) + bigIntToUint8List(s))));
  }
  throw Exception(
      'Unsupported algorithm ${toVerify.signatureAlgorithm.algorithm.name}');
}

Future<bool> _x509Checks(X509Certificate toVerify, X509Certificate issuer,
    [DateTime? checkDate]) async {
  if (toVerify.tbsCertificate.version != 3) {
    throw Exception(
        'Version ${toVerify.tbsCertificate.version} is not supported. Only supported Version is Version 3.');
  }
  checkDate ??= DateTime.now();
  if (toVerify.tbsCertificate.validity!.notAfter.isBefore(checkDate)) {
    throw Exception(
        'Certificate is not valid after ${toVerify.tbsCertificate.validity!.notAfter.toIso8601String()}');
  }
  if (toVerify.tbsCertificate.validity!.notBefore.isAfter(checkDate)) {
    throw Exception(
        'Certificate is not valid before ${toVerify.tbsCertificate.validity!.notBefore.toIso8601String()}');
  }

  //Check if distinguished name of issuer cert is equal to issuer dn in toVerify
  var issuerCertDN = issuer.tbsCertificate.subject?.toAsn1().encodedBytes;
  var issuerDN = toVerify.tbsCertificate.issuer?.toAsn1().encodedBytes;
  if (!listsEqual(issuerCertDN, issuerDN)) {
    throw Exception(
        'Issuer of certificate do not match subject of presented issuer certificate');
  }

  //Check for BasicConstraints of issuer cert -> must be included and ca must be true
  var extensionsIssuer = issuer.tbsCertificate.extensions;
  if (extensionsIssuer != null && extensionsIssuer.isNotEmpty) {
    var asMap = {
      for (var item in extensionsIssuer) item.extnId: item.extnValue
    };
    if (asMap.containsKey(ObjectIdentifier([2, 5, 29, 19]))) {
      var basicConstraints =
          asMap[ObjectIdentifier([2, 5, 29, 19])] as BasicConstraints;
      if (!basicConstraints.cA) {
        throw Exception(
            'Issuer Certificate is not a CA certificate (BasicConstraints.ca is false');
      } else {
        //check keyUsage
        if (asMap.containsKey(ObjectIdentifier([2, 5, 29, 15]))) {
          var keyUsage = asMap[ObjectIdentifier([2, 5, 29, 15])] as KeyUsage;
          if (!keyUsage.keyCertSign) {
            throw Exception('Key is not allowed to sign certificates');
          }
        }
      }
    } else {
      throw Exception(
          'Basic constraints extension needed for issuer certificate');
    }
  }

  //is there a CRL?
  var extensions = toVerify.tbsCertificate.extensions;
  if (extensions != null && extensions.isNotEmpty) {
    var asMap = {for (var item in extensions) item.extnId: item.extnValue};
    if (asMap.containsKey(ObjectIdentifier([2, 5, 29, 31]))) {
      var crlPoints =
          asMap[ObjectIdentifier([2, 5, 29, 31])] as CrlDistributionPoints;
      for (var p in crlPoints.points) {
        if (p.name != null) {
          if (p.name?.fullName?.choice == 6) {
            //We have a url to get the crl from
            var url = (p.name!.fullName!.contents as ASN1IA5String).stringValue;
            var res = await get(Uri.parse(url));
            var crl = CertificateRevocationList.fromAsn1(
                ASN1Parser(res.bodyBytes).nextObject() as ASN1Sequence);
            if (!(await verifyCertificate(crl, issuer, checkDate))) {
              throw Exception('Certificate Revocation List is not valid');
            }
            if (crl.tbsCertificateList.revokedCertificates != null &&
                crl.tbsCertificateList.revokedCertificates!
                    .containsKey(toVerify.tbsCertificate.serialNumber)) {
              var revoked = crl.tbsCertificateList
                  .revokedCertificates![toVerify.tbsCertificate.serialNumber]!;
              if (revoked.revocationDate.isAfter(checkDate)) {
                throw Exception(
                    'Certificate was revoked at ${revoked.revocationDate.toIso8601String()}');
              }
            }
          }
        }
      }
    }
  }
  return true;
}

bool _crlChecks(CertificateRevocationList toVerify, X509Certificate issuer,
    [DateTime? checkDate]) {
  checkDate ??= DateTime.now();
  if (toVerify.tbsCertificateList.nextUpdate.isBefore(checkDate)) {
    throw Exception(
        'Old CRL. Should be updated at ${toVerify.tbsCertificateList.nextUpdate}');
  }
  return true;
}

//Source: https://stackoverflow.com/questions/61075549/bigint-to-bytes-array-in-dart
Uint8List bigIntToUint8List(BigInt bigInt) =>
    bigIntToByteData(bigInt).buffer.asUint8List();

ByteData bigIntToByteData(BigInt bigInt) {
  final data = ByteData((bigInt.bitLength / 8).ceil());
  var _bigInt = bigInt;

  for (var i = 1; i <= data.lengthInBytes; i++) {
    data.setUint8(data.lengthInBytes - i, _bigInt.toUnsigned(8).toInt());
    _bigInt = _bigInt >> 8;
  }

  return data;
}
