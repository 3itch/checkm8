
from pyasn1.type import univ, namedtype, tag
from pyasn1.codec.der import decoder as der_decoder


#RFC2313
#RSAPrivateKey ::= SEQUENCE {
#  version Version,
#  modulus INTEGER, -- n
#  publicExponent INTEGER, -- e
#  privateExponent INTEGER, -- d
#  prime1 INTEGER, -- p
#  prime2 INTEGER, -- q
#  exponent1 INTEGER, -- d mod (p-1)
#  exponent2 INTEGER, -- d mod (q-1)
#  coefficient INTEGER -- (inverse of q) mod p
#}
class RSAPrivateKey(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('Version', univ.Integer()),
    namedtype.NamedType('modulus', univ.Integer()),
    namedtype.NamedType('publicExponent', univ.Integer()),
    namedtype.NamedType('privateExponent', univ.Integer()),
    namedtype.NamedType('prime1', univ.Integer()),
    namedtype.NamedType('prime2', univ.Integer()),
    namedtype.NamedType('exponent1', univ.Integer()),
    namedtype.NamedType('exponent2', univ.Integer()),
    namedtype.NamedType('coefficient', univ.Integer())
  )


#RFC3447
#RSAPublicKey ::= SEQUENCE {
#    modulus           INTEGER,  -- n
#    publicExponent    INTEGER   -- e
#}
class RSAPublicKey(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('modulus', univ.Integer()),
    namedtype.NamedType('publicExponent', univ.Integer())
  )


#RFC 5480
#AlgorithmIdentifier ::= SEQUENCE {
#  algorithm       OBJECT IDENTIFIER,
#  parameters      ANY DEFINED BY algorithm OPTIONAL
#}
class AlgorithmIdentifier(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
    namedtype.OptionalNamedType('parameters', univ.Any())
  )


#RFC 5480
#SubjectPublicKeyInfo  ::=  SEQUENCE  {
#  algorithm         AlgorithmIdentifier,
#  subjectPublicKey  BIT STRING
#}
class SubjectPublicKeyInfo(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('algorithm', AlgorithmIdentifier()),
    namedtype.NamedType('subjectPublicKey', univ.BitString())
  )


#RFC 5912
#ECParameters ::= CHOICE {
#    namedCurve      CURVE.&id({NamedCurve})
#    -- implicitCurve   NULL
#      -- implicitCurve MUST NOT be used in PKIX
#    -- specifiedCurve  SpecifiedCurve
#      -- specifiedCurve MUST NOT be used in PKIX
#      -- Details for specifiedCurve can be found in [X9.62]
#      -- Any future additions to this CHOICE should be coordinated
#      -- with ANSI X.9.
#   }
#
class ECParameters(univ.Choice):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('namedCurve', univ.ObjectIdentifier()),
    namedtype.NamedType('implicitCurve', univ.Null()),
    namedtype.NamedType('specifiedCurve', univ.ObjectIdentifier())
  )


#RFC 5915
#ECPrivateKey ::= SEQUENCE {
#  version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
#  privateKey     OCTET STRING,
#  parameters [0] EXPLICIT ECParameters {{ NamedCurve }} OPTIONAL,
#  publicKey  [1] EXPLICIT BIT STRING OPTIONAL
#}
#
# PKIX compliant
class ECPrivateKey(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('version', univ.Integer()),
    namedtype.NamedType('privateKey', univ.OctetString()),
    #namedtype.NamedType('ECParameters', ECParameters().subtype(
    #          explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    namedtype.OptionalNamedType('ECParameters', univ.ObjectIdentifier().subtype(
              explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    namedtype.OptionalNamedType('publicKey', univ.BitString().subtype(
              explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
  )


#DigestInfo ::= SEQUENCE {
#    digestAlgorithm AlgorithmIdentifier,
#    digest OCTET STRING
#}



#ECDSASignature ::= SEQUENCE {
#    r   INTEGER,
#    s   INTEGER
#}
#
class ECDSASignature(univ.Sequence):
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('r', univ.Integer()),
    namedtype.NamedType('s', univ.Integer())
  )


