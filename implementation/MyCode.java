package implementation;

import code.GuiException;
import gui.Constants;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.eac.ECDSAPublicKey;
import org.bouncycastle.asn1.eac.RSAPublicKey;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
//import sun.security.ec.ECPublicKeyImpl;
//import sun.security.rsa.RSAPublicKeyImpl;
import x509.v3.CodeV3;
import x509.v3.GuiV3;

//import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.cert.Extension;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;

public class MyCode extends CodeV3 {


    KeyStore keyStore;
    static String keyStorePass = "pass";
    static String keyStorePathAbsolute = "C:\\Users\\Pedja\\Desktop\\FAKS\\ZP\\Projekat\\myKeystore.p12";
    static String keyStorePathRelative = "..\\myKeystore.p12";
    PublicKey requestersPublicKey;

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);

        Security.addProvider(new BouncyCastleProvider());
        if (Security.getProvider("BC") == null) {
            throw new Error("Nema Bouncy Castle providera!");
        }
    }

    //poziva se na pocetku, ako ne postoji localKeystore na zadatoj putanji, napravi ga!
    @Override
    public Enumeration<String> loadLocalKeystore() {

        try {
            keyStore = KeyStore.getInstance("pkcs12");

            FileInputStream inputStream;
            try {
                inputStream = new FileInputStream(keyStorePathRelative);
                keyStore.load(inputStream, keyStorePass.toCharArray());

            } catch (FileNotFoundException e) {
                GuiV3.reportError("Ne postoji localKeyStore, pravi se novi!");
                resetLocalKeystore();

            }

            return keyStore.aliases();

        } catch (KeyStoreException e) {
            e.printStackTrace();
            GuiV3.reportError(e);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void resetLocalKeystore() {
        File localKeyStore = new File(keyStorePathRelative);
        FileOutputStream outputStream = null;
        try {

            outputStream = new FileOutputStream(localKeyStore);
            keyStore.load(null, keyStorePass.toCharArray());
            keyStore.store(outputStream, keyStorePass.toCharArray());
            outputStream.flush();
            outputStream.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

    }

    public void saveKeystore() {
        File localKeyStore = new File(keyStorePathRelative);
        FileOutputStream outputStream = null;
        try {

            outputStream = new FileOutputStream(localKeyStore);
            keyStore.store(outputStream, keyStorePass.toCharArray());
            outputStream.flush();
            outputStream.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

    }

    public void setNoncriticalExtensions(X509Certificate cert) {
        Set<String> noncritSet = cert.getNonCriticalExtensionOIDs();
        if (noncritSet != null && !noncritSet.isEmpty()) {
            for (String oid : noncritSet) {
                byte[] data = cert.getExtensionValue(oid);
                switch (oid) {
                    case "2.5.29.19"://basic constraint

                        ASN1OctetString bcsOc = ASN1OctetString.getInstance(data);
                        BasicConstraints bcs = BasicConstraints.getInstance(bcsOc.getOctets());

                        this.access.setCritical(Constants.BC, false);
                        this.access.setCA(bcs.isCA());
                        if (bcs.isCA()) {
                            BigInteger pathLen = bcs.getPathLenConstraint();
                            if (pathLen != null) {
                                this.access.setPathLen(String.valueOf(bcs.getPathLenConstraint()));
                            }
                        }
                        break;

                    case "2.5.29.9"://subject directory attributes

                        ASN1OctetString sdaOc = ASN1OctetString.getInstance(data);
                        SubjectDirectoryAttributes sda = SubjectDirectoryAttributes.getInstance(sdaOc.getOctets());

                        String helperString;
                        Vector<Attribute> attVector = sda.getAttributes();
                        for (Attribute attribute : attVector) {
                            if (attribute.getAttrType().equals(BCStyle.DATE_OF_BIRTH)) {
                                ASN1UTCTime dateOfBirthTime = (ASN1UTCTime) attribute.getAttrValues().getObjectAt(0);
                                SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd");
                                try {
                                    this.access.setDateOfBirth(simpleDateFormat.format(dateOfBirthTime.getDate()));
                                } catch (ParseException e) {
                                    e.printStackTrace();
                                }
                            } else if (attribute.getAttrType().equals(BCStyle.PLACE_OF_BIRTH)) {
                                DEROctetString derOctetString = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
                                this.access.setSubjectDirectoryAttribute(Constants.POB, new String(derOctetString.getOctets()));
                            } else if (attribute.getAttrType().equals(BCStyle.COUNTRY_OF_CITIZENSHIP)) {
                                DEROctetString derOctetString = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
                                this.access.setSubjectDirectoryAttribute(Constants.COC, new String(derOctetString.getOctets()));
                            } else if (attribute.getAttrType().equals(BCStyle.GENDER)) {
                                DEROctetString derOctetString = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
                                this.access.setGender(new String(derOctetString.getOctets()));
                            }
                        }
                        this.access.setCritical(Constants.DSA, false);

                        //System.out.println(data);
                        break;

                    case "2.5.29.14"://subjec key identifier
                        //System.out.println("SKI noncritical:" + data);

                        ASN1OctetString skiOc = ASN1OctetString.getInstance(data);
                        SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(skiOc.getOctets());

                        String skid = "";
                        try {
                            skid = new String(skiOc.toString());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                        this.access.setSubjectKeyID(skid);
                        this.access.setEnabledSubjectKeyID(true);
                        this.access.setCritical(Constants.SKID, false);
                }

            }
        }
    }

    public void setCriticalExtensions(X509Certificate cert) {
        Set<String> critSet = cert.getCriticalExtensionOIDs();
        if (critSet != null && !critSet.isEmpty()) {
            for (String oid : critSet) {
                byte[] data = cert.getExtensionValue(oid);
                switch (oid) {
                    case "2.5.29.19"://basic constraint

                        ASN1OctetString bcsOc = ASN1OctetString.getInstance(data);
                        BasicConstraints bcs = BasicConstraints.getInstance(bcsOc.getOctets());

                        this.access.setCritical(Constants.BC, true);
                        this.access.setCA(bcs.isCA());
                        if (bcs.isCA()) {
                            BigInteger pathLen = bcs.getPathLenConstraint();
                            if (pathLen != null) {
                                this.access.setPathLen(String.valueOf(bcs.getPathLenConstraint()));
                            }
                        }

                        break;

                    case "2.5.29.9"://subject directory attributes

                        ASN1OctetString sdaOc = ASN1OctetString.getInstance(data);
                        SubjectDirectoryAttributes sda = SubjectDirectoryAttributes.getInstance(sdaOc.getOctets());

                        Vector<Attribute> attVector = sda.getAttributes();
                        for (Attribute attribute : attVector) {
                            if (attribute.getAttrType().equals(BCStyle.DATE_OF_BIRTH)) {
                                ASN1UTCTime dateOfBirthTime = (ASN1UTCTime) attribute.getAttrValues().getObjectAt(0);
                                SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd");
                                try {
                                    this.access.setDateOfBirth(simpleDateFormat.format(dateOfBirthTime.getDate()));
                                } catch (ParseException e) {
                                    e.printStackTrace();
                                }
                            } else if (attribute.getAttrType().equals(BCStyle.PLACE_OF_BIRTH)) {
                                DEROctetString derOctetString = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
                                this.access.setSubjectDirectoryAttribute(Constants.POB, new String(derOctetString.getOctets()));
                            } else if (attribute.getAttrType().equals(BCStyle.COUNTRY_OF_CITIZENSHIP)) {
                                DEROctetString derOctetString = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
                                this.access.setSubjectDirectoryAttribute(Constants.COC, new String(derOctetString.getOctets()));
                            } else if (attribute.getAttrType().equals(BCStyle.GENDER)) {
                                DEROctetString derOctetString = (DEROctetString) attribute.getAttrValues().getObjectAt(0);
                                this.access.setGender(new String(derOctetString.getOctets()));
                            }
                        }
                        this.access.setCritical(Constants.DSA, true);

                        break;

                    case "2.5.29.14"://subject key identifier

                        ASN1OctetString skiOc = ASN1OctetString.getInstance(data);
                        SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(skiOc.getOctets());

                        String skid = "";
                        try {
                            skid = new String(skiOc.toString());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }

                        this.access.setSubjectKeyID(skid);
                        this.access.setEnabledSubjectKeyID(true);
                        this.access.setCritical(Constants.SKID, true);

                        break;
                }

            }
        }
    }

    static boolean checkIfIsSelfSigned(X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());
        } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
            return false;
        }
        return true;
    }

    static boolean checkIfIsCertificateAuthority(X509Certificate cert) {
        return cert.getBasicConstraints() != -1;
    }

    public String getSetFromCurve(String curve) {
        String[] curves = {"prime256v1",
                "secp256k1",
                "secp256r1",
                "secp384r1",
                "secp521r1",
                "sect283k1",
                "sect283r1",
                "sect409k1",
                "sect409r1",
                "sect571k1",
                "sect571r1",
                "P-256",
                "P-384",
                "P-521",
                "B-283",
                "B-409",
                "B-571"};
        int cnt = 0;
        for (String c : curves) {
            if (c.compareTo(curve) == 0) {
                if (cnt == 1)
                    return "X9.62";
                else if (cnt <= 10)
                    return "SEC";
                else return "NIST";
            }
            cnt++;
        }
        return null;
    }

    @Override
    public int loadKeypair(String s) {


        try {

            X509Certificate cert = (X509Certificate) keyStore.getCertificate(s);
            Certificate[] chain = keyStore.getCertificateChain(s);

            this.access.setNotAfter(cert.getNotAfter());
            this.access.setNotBefore(cert.getNotBefore());
            this.access.setSerialNumber(String.valueOf(cert.getSerialNumber()));

            PublicKey pu = cert.getPublicKey();

            this.access.setVersion(2);
            this.access.setPublicKeyAlgorithm(cert.getPublicKey().getAlgorithm());
            this.access.setPublicKeyDigestAlgorithm(cert.getSigAlgName());
            this.access.setSubjectSignatureAlgorithm(cert.getPublicKey().getAlgorithm());

            System.out.println(getCertPublicKeyAlgorithm(s));

            String pkalg = getCertPublicKeyAlgorithm(s);
            if (pkalg.equals("RSA")) {
                this.access.setPublicKeyParameter(getCertPublicKeyParameter(s));
            } else if (pkalg.equals("EC")) {
                String kriva = getCertPublicKeyParameter(s);
                this.access.setPublicKeyParameter(getSetFromCurve(kriva));
                this.access.setPublicKeyECCurve(kriva);
            }

            //setovanje subject info
            X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();//X500Name(subjectData.getName());

            String correctedName = correctNameString(x500name.toString());
            this.access.setSubject(correctedName);

            //end setovanje subject info

            //setovanje ekstenzija
            setCriticalExtensions(cert);
            setNoncriticalExtensions(cert);
            //end setovanje ekstenzija

            //setovanje CA info
            X500Name issuerData = new X500Name(cert.getIssuerDN().getName());
            String CAdata = correctNameString(cert.getIssuerDN().toString()); // popravka cert.getIssuerDN() stringa da ne puca
            this.access.setIssuer(CAdata);
            this.access.setIssuerSignatureAlgorithm(cert.getSigAlgName());
            //end setovanje CA info

            //provera certificate chaina

            if (keyStore.isCertificateEntry(s)) { // sertifikati koje je user importovao su trusted!
                return 2;
            } else {
                if (checkIfIsSelfSigned(cert)) {
                    return 0;
                } else {
                    return 1;
                }
            }

            //end provera certificate chaina


        } catch (KeyStoreException e) {
            e.printStackTrace();
            return -1;
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        return -1;

    }

    public String correctNameString(String nameBefore) {
        StringBuilder sb = new StringBuilder("");
        String[] splits = nameBefore.split(",");
        for (String item : splits) {

            String stripped = item.trim();
            String[] terms = stripped.split("=");

            if (terms[1].trim().length() > 0) {
                sb.append(stripped);
                sb.append(",");
            }
        }
        return sb.toString();
    }

    @Override
    public boolean saveKeypair(String s) {

        KeyPair kp;

        String curve = this.access.getPublicKeyECCurve();

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");

            ECParameterSpec ecparam = ECNamedCurveTable.getParameterSpec(curve);

            kpg.initialize(ecparam, new SecureRandom());

            kp = kpg.generateKeyPair();

            X509Certificate certificate = generateCertificate(kp, true, null, null);
            if (certificate == null) {
                return false;
            }

            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = certificate;


            keyStore.setKeyEntry(s, kp.getPrivate(), null, chain);

            saveKeystore();

            return true;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }


        return false;
    }

    public X509Certificate generateCertificate(KeyPair kp, boolean selfSigning, String signerName, String signingAlgorithm) {


        BigInteger serialNum = new BigInteger(this.access.getSerialNumber());
        Date dateNotBefore = this.access.getNotBefore();
        Date dateNotAfter = this.access.getNotAfter();
        String subject = this.access.getSubject();
        Locale l = Locale.forLanguageTag("sr-Latn-RS");


        X500NameBuilder nameBuilder = new X500NameBuilder(X500Name.getDefaultStyle());

        if (!this.access.getSubjectCommonName().isEmpty()) {
            nameBuilder.addRDN(BCStyle.CN, this.access.getSubjectCommonName());
        }
        if (!this.access.getSubjectOrganizationUnit().isEmpty()) {
            nameBuilder.addRDN(BCStyle.OU, this.access.getSubjectOrganizationUnit());
        }
        if (!this.access.getSubjectLocality().isEmpty()) {
            nameBuilder.addRDN(BCStyle.L, this.access.getSubjectLocality());
        }
        if (!this.access.getSubjectState().isEmpty()) {
            nameBuilder.addRDN(BCStyle.ST, this.access.getSubjectState());
        }
        if (!this.access.getSubjectCountry().isEmpty()) {
            nameBuilder.addRDN(BCStyle.C, this.access.getSubjectCountry());
        }
        if (!this.access.getSubjectOrganization().isEmpty()) {
            nameBuilder.addRDN(BCStyle.O, this.access.getSubjectOrganization());
        }

        X500Name subjectName = nameBuilder.build();


        //alg
        String publicKeySet = this.access.getPublicKeyParameter();//set
        String publicKeyAlgorithm = this.access.getPublicKeyAlgorithm();//EC
        String publicECCurve = this.access.getPublicKeyECCurve();//curve

        //hash fja
        String publicKeyDigest = this.access.getPublicKeyDigestAlgorithm();//SHA

        SubjectPublicKeyInfo publicKeyInfoField = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());

        X509v3CertificateBuilder cb = new X509v3CertificateBuilder(subjectName, serialNum, dateNotBefore, dateNotAfter, l, subjectName, publicKeyInfoField);

        //basic constraint

        boolean isCritical = this.access.isCritical(Constants.BC);
        boolean isCA = this.access.isCA();
        int pathLen;
        if (this.access.getPathLen().length() > 0) {
            pathLen = Integer.parseInt(this.access.getPathLen());

        } else {
            pathLen = -1;
        }

        try {
            if (isCA) {
                if (pathLen != -1) {
                    cb.addExtension(X509Extensions.BasicConstraints, isCritical, new BasicConstraints(pathLen));
                } else {
                    cb.addExtension(X509Extensions.BasicConstraints, isCritical, new BasicConstraints(true));
                }
            } else {
                cb.addExtension(X509Extensions.BasicConstraints, isCritical, new BasicConstraints(false));
            }
        } catch (CertIOException e) {
            e.printStackTrace();
        }
        //end basic constraints


        //subject key identifier

        isCritical = this.access.isCritical(Constants.SKID);
        boolean isEnabledSubjectKeyID = this.access.getEnabledSubjectKeyID();
        if (isEnabledSubjectKeyID) {
            try {
                SubjectKeyIdentifier ski = new SubjectKeyIdentifier(publicKeyInfoField.getEncoded());
                cb.addExtension(X509Extensions.SubjectKeyIdentifier, isCritical, ski);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        //end subject key identifier


        //subject directory attributes

        isCritical = this.access.isCritical(Constants.SDA);
        String gender = this.access.getGender();
        String dateOfBirth = this.access.getDateOfBirth();
        String placeOfBirth = this.access.getSubjectDirectoryAttribute(Constants.POB);
        String countryOfCitizenship = this.access.getSubjectDirectoryAttribute(Constants.COC);

        boolean greskaSDA = false;

        boolean sviPrazniSDA = false;



        if (this.access.getGender().isEmpty()
                || this.access.getDateOfBirth().isEmpty()
                || this.access.getSubjectDirectoryAttribute(Constants.POB).isEmpty()
                || this.access.getSubjectDirectoryAttribute(Constants.COC).isEmpty()) {
            if (isCritical) {
                GuiV3.reportError("SDA podesen kao kriticna ekstenzija, a nisu sva polja popunjena!");
                greskaSDA = true;
                return null;
            } else {
                if (!this.access.getGender().isEmpty()
                        || !this.access.getDateOfBirth().isEmpty()
                        || !this.access.getSubjectDirectoryAttribute(Constants.POB).isEmpty()
                        || !this.access.getSubjectDirectoryAttribute(Constants.COC).isEmpty())//da li postoji barem jedno popunjeno polje
                {
                    GuiV3.reportError("Molimo popunite ili sva polja za SDA ekstenziju ili nijedno");
                    greskaSDA = true;
                    return null;
                } else {
                    sviPrazniSDA = true;
                }
            }
        }
        if (!sviPrazniSDA) {
            Vector<Attribute> attributes = new Vector<>();

            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd");
            Date dateOfBirthDate = null;
            try {
                dateOfBirthDate = simpleDateFormat.parse(dateOfBirth);
            } catch (ParseException e) {
                e.printStackTrace();
            }

            attributes.add(new Attribute(BCStyle.DATE_OF_BIRTH, new DERSet(new Time(dateOfBirthDate))));
            attributes.add(new Attribute(BCStyle.PLACE_OF_BIRTH, new DERSet(new DEROctetString(placeOfBirth.getBytes()))));
            attributes.add(new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, new DERSet(new DEROctetString(countryOfCitizenship.getBytes()))));
            attributes.add(new Attribute(BCStyle.GENDER, new DERSet(new DEROctetString(gender.getBytes()))));

            SubjectDirectoryAttributes subjectDirectoryAttributes = new SubjectDirectoryAttributes(attributes);
            try {
                cb.addExtension(X509Extensions.SubjectDirectoryAttributes, isCritical, subjectDirectoryAttributes);
            } catch (CertIOException e) {
                e.printStackTrace();
            }
        }

        //end subject directory attributes

        try {

            if (selfSigning)

            {
                AlgorithmIdentifier cryptoalg = new DefaultSignatureAlgorithmIdentifierFinder().find(publicKeyDigest);
                AlgorithmIdentifier hashalg = new DefaultDigestAlgorithmIdentifierFinder().find(cryptoalg);

                AsymmetricKeyParameter akp = PrivateKeyFactory.createKey(kp.getPrivate().getEncoded());

                ContentSigner signer = new BcECContentSignerBuilder(cryptoalg, hashalg).build(akp);

                X509CertificateHolder ch = cb.build(signer);

                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                InputStream in = new ByteArrayInputStream(ch.getEncoded());
                X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);

                return cert;
            } else {
                AlgorithmIdentifier cryptoalg = new DefaultSignatureAlgorithmIdentifierFinder().find(signingAlgorithm);
                AlgorithmIdentifier hashalg = new DefaultDigestAlgorithmIdentifierFinder().find(cryptoalg);

                AsymmetricKeyParameter akp = PrivateKeyFactory.createKey(keyStore.getKey(signerName, null).getEncoded());
                //AsymmetricKeyParameter akp = PrivateKeyFactory.createKey(kp.getPrivate().getEncoded());

                ContentSigner signer = new BcECContentSignerBuilder(cryptoalg, hashalg).build(akp);

                X509CertificateHolder ch = cb.build(signer);

                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                InputStream in = new ByteArrayInputStream(ch.getEncoded());
                X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);

                return cert;
            }

        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return null;
    }


    @Override
    public boolean removeKeypair(String s) {

        try {
            if (keyStore.containsAlias(s)) {
                keyStore.deleteEntry(s);
                saveKeystore();
                return true;
            }
            return false;
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean importKeypair(String s, String s1, String s2) {
        try {

            if (keyStore.containsAlias(s)) {
                return false;
            }

            KeyStore importKeyStore = KeyStore.getInstance("PKCS12");
            importKeyStore.load(new FileInputStream(s1), s2.toCharArray());

            Enumeration<String> alijasi = importKeyStore.aliases();
            int elemcount = 0;

            while (alijasi.hasMoreElements()) {
                elemcount++;
                if (elemcount > 1) {
                    break;
                }
                String alias = alijasi.nextElement();
                keyStore.setKeyEntry(s, importKeyStore.getKey(alias, s2.toCharArray()), new char[0], importKeyStore
                        .getCertificateChain(alias));
            }
            if (elemcount > 1) {
                GuiV3.reportError("PKCS12 fajl ne sme sadrzati vise od jednog entry-a!");
                return false;
            }
            saveKeystore();
            return true;

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | UnrecoverableEntryException e) {
            e.printStackTrace();
            return false;
        }

    }

    @Override
    public boolean exportKeypair(String s, String s1, String s2) {
        try {
            KeyStore export = KeyStore.getInstance("PKCS12");

            export.load(null, s2.toCharArray());
            export.setKeyEntry(s, keyStore.getKey(s, new char[0]), s2.toCharArray(), keyStore.getCertificateChain(s));

            OutputStream outputStream = new FileOutputStream(s1);
            export.store(outputStream, s2.toCharArray());
            outputStream.flush();
            outputStream.close();
        } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @Override
    public boolean importCertificate(String s, String s1) {
        try {
            File file = new File(s);

            try (BufferedInputStream buff = new BufferedInputStream(new FileInputStream(file))) {
                CertificateFactory certf = CertificateFactory.getInstance("X.509");
                if (buff.available() > 0) {
                    Certificate cert = certf.generateCertificate(buff);
                    keyStore.setCertificateEntry(s1, cert);
                    saveKeystore();
                }
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    public boolean exportCertificate(String file, String keypair_name, int encoding, int format) {
        try (FileOutputStream out = new FileOutputStream(file)) {

            Certificate cert = keyStore.getCertificateChain(keypair_name)[0];
            if (encoding == 0) {  // DER format, nikad se ne eksportuje chain, head only
                out.write(cert.getEncoded());
            } else { // PEM format

                if (format == 0) // head only
                {

                    out.write("-----BEGIN CERTIFICATE-----".getBytes());
                    out.write(java.util.Base64.getEncoder().withoutPadding().encode(cert.getEncoded()));
                    out.write("-----END CERTIFICATE-----".getBytes());

                } else {
                    Certificate[] chain = keyStore.getCertificateChain(keypair_name);

                    if (chain == null) {
                        chain = new Certificate[1];
                        chain[0] = cert;
                    }
                    for (Certificate current_target : chain) {
                        out.write("-----BEGIN CERTIFICATE-----".getBytes());
                        out.write(java.util.Base64.getEncoder().withoutPadding().encode(current_target.getEncoded()));
                        out.write("-----END CERTIFICATE-----".getBytes());
                    }

                }
            }

            out.flush();
            out.close();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    public boolean exportCSR(String file, String keypair_name, String algorithm) {

        File f = new File(file);

        try {
            FileOutputStream fops = new FileOutputStream(f);
            if (keyStore.isCertificateEntry(keypair_name)) {
                GuiV3.reportError("Ne moze se praviti CSR za potpisan sertifikat!");
                return false;
            }

            X509Certificate cert = (X509Certificate) keyStore.getCertificate(keypair_name);
            //X500Principal subjectData = cert.getSubjectX500Principal();
            //setovanje subject info
            X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();// X500Name(subjectData.getName());
            String correctedSubject = correctNameString(x500name.toString());

            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(cert.getPublicKey().getEncoded());

            PKCS10CertificationRequestBuilder rb = new PKCS10CertificationRequestBuilder(x500name, spki);

            ContentSigner csr = new JcaContentSignerBuilder(algorithm).build((PrivateKey) keyStore.getKey(keypair_name, null));
            fops.write(rb.build(csr).getEncoded());
            fops.flush();
            fops.close();

            return true;

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }

        return false;
    }

    @Override
    public String importCSR(String file) {

        File f = new File(file);

        byte[] csrBytes = new byte[(int) f.length()];
        try {
            FileInputStream fips = new FileInputStream(f);
            fips.read(csrBytes);
            JcaPKCS10CertificationRequest csr = new JcaPKCS10CertificationRequest(csrBytes);
            PublicKey pu = csr.getPublicKey();
            X500Name x500Name = csr.getSubject();

            requestersPublicKey = pu;
            return correctNameString(x500Name.toString());


        } catch (FileNotFoundException e) {
            System.out.println("File Not Found.");
            e.printStackTrace();
        } catch (IOException e1) {
            System.out.println("Error Reading The File.");
            e1.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public boolean signCSR(String file, String keypair_name, String algorithm) {

        File f = new File(file);

        BigInteger serialNum = new BigInteger(this.access.getSerialNumber());
        Date dateNotBefore = this.access.getNotBefore();
        Date dateNotAfter = this.access.getNotAfter();
        String subject = this.access.getSubject();
        Locale l = Locale.forLanguageTag("sr-Latn-RS");
        //Certificate cert = generateCertificate();

        X500NameBuilder nameBuilder = new X500NameBuilder(X500Name.getDefaultStyle());

        if (!this.access.getSubjectCommonName().isEmpty()) {
            nameBuilder.addRDN(BCStyle.CN, this.access.getSubjectCommonName());
        }
        if (!this.access.getSubjectOrganizationUnit().isEmpty()) {
            nameBuilder.addRDN(BCStyle.OU, this.access.getSubjectOrganizationUnit());
        }
        if (!this.access.getSubjectLocality().isEmpty()) {
            nameBuilder.addRDN(BCStyle.L, this.access.getSubjectLocality());
        }
        if (!this.access.getSubjectState().isEmpty()) {
            nameBuilder.addRDN(BCStyle.ST, this.access.getSubjectState());
        }
        if (!this.access.getSubjectCountry().isEmpty()) {
            nameBuilder.addRDN(BCStyle.C, this.access.getSubjectCountry());
        }
        if (!this.access.getSubjectOrganization().isEmpty()) {
            nameBuilder.addRDN(BCStyle.O, this.access.getSubjectOrganization());
        }

        X500Name subjectName = nameBuilder.build();
        X500Name issuerName = null;
        try {

            X509Certificate issuerCert = (X509Certificate) keyStore.getCertificate(keypair_name);
            //X500Principal issuerData = issuerCert.getSubjectX500Principal();
            issuerName = new JcaX509CertificateHolder(issuerCert).getSubject();//X500Name(issuerData.getName());

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }

        //alg
        String publicKeySet = this.access.getPublicKeyParameter();//set
        String publicKeyAlgorithm = this.access.getPublicKeyAlgorithm();//EC
        String publicECCurve = this.access.getPublicKeyECCurve();//curve

        //hash fja
        String publicKeyDigest = this.access.getPublicKeyDigestAlgorithm();//SHA

        SubjectPublicKeyInfo publicKeyInfoField = SubjectPublicKeyInfo.getInstance(requestersPublicKey.getEncoded());

        X509v3CertificateBuilder cb = new X509v3CertificateBuilder(issuerName, serialNum, dateNotBefore, dateNotAfter, l, subjectName, publicKeyInfoField);

        //basic constraint

        boolean isCritical = this.access.isCritical(Constants.BC);
        boolean isCA = this.access.isCA();
        int pathLen;
        if (this.access.getPathLen().length() > 0) {
            pathLen = Integer.parseInt(this.access.getPathLen());

        } else {
            pathLen = -1;
        }

        try {
            if (isCA) {
                if (pathLen != -1) {
                    cb.addExtension(X509Extensions.BasicConstraints, isCritical, new BasicConstraints(pathLen));
                } else {
                    cb.addExtension(X509Extensions.BasicConstraints, isCritical, new BasicConstraints(true));
                }
            } else {
                cb.addExtension(X509Extensions.BasicConstraints, isCritical, new BasicConstraints(false));
            }
        } catch (CertIOException e) {
            e.printStackTrace();
        }
        //end basic constraints


        //subject key identifier

        isCritical = this.access.isCritical(Constants.SKID);
        boolean isEnabledSubjectKeyID = this.access.getEnabledSubjectKeyID();
        if (isEnabledSubjectKeyID) {
            try {
                SubjectKeyIdentifier ski = new SubjectKeyIdentifier(publicKeyInfoField.getEncoded());
                cb.addExtension(X509Extensions.SubjectKeyIdentifier, isCritical, ski);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        //end subject key identifier


        //subject directory attributes

        isCritical = this.access.isCritical(Constants.SDA);
        String gender = this.access.getGender();
        String dateOfBirth = this.access.getDateOfBirth();
        String placeOfBirth = this.access.getSubjectDirectoryAttribute(Constants.POB);
        String countryOfCitizenship = this.access.getSubjectDirectoryAttribute(Constants.COC);

        boolean greskaSDA = false;

        boolean sviPrazniSDA = false;
        if (isCritical)
        {
            GuiV3.reportError("SDA ne sme biti kritican da bi SSL radio!");
            return false;
        }

        if (this.access.getGender().isEmpty()
                || this.access.getDateOfBirth().isEmpty()
                || this.access.getSubjectDirectoryAttribute(Constants.POB).isEmpty()
                || this.access.getSubjectDirectoryAttribute(Constants.COC).isEmpty()) {
            if (isCritical) {
                GuiV3.reportError("SDA podesen kao kriticna ekstenzija, a nisu sva polja popunjena!");
                greskaSDA = true;
                return false;
            } else {
                if (!this.access.getGender().isEmpty()
                        || !this.access.getDateOfBirth().isEmpty()
                        || !this.access.getSubjectDirectoryAttribute(Constants.POB).isEmpty()
                        || !this.access.getSubjectDirectoryAttribute(Constants.COC).isEmpty())//da li postoji barem jedno popunjeno polje
                {
                    GuiV3.reportError("Molimo popunite ili sva polja za SDA ekstenziju ili nijedno");
                    greskaSDA = true;
                    return false;
                } else {
                    sviPrazniSDA = true;
                }
            }
        }
        if (!sviPrazniSDA) {
            Vector<Attribute> attributes = new Vector<>();

            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMdd");
            Date dateOfBirthDate = null;
            try {
                dateOfBirthDate = simpleDateFormat.parse(dateOfBirth);
            } catch (ParseException e) {
                e.printStackTrace();
            }

            attributes.add(new Attribute(BCStyle.DATE_OF_BIRTH, new DERSet(new Time(dateOfBirthDate))));
            attributes.add(new Attribute(BCStyle.PLACE_OF_BIRTH, new DERSet(new DEROctetString(placeOfBirth.getBytes()))));
            attributes.add(new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, new DERSet(new DEROctetString(countryOfCitizenship.getBytes()))));
            attributes.add(new Attribute(BCStyle.GENDER, new DERSet(new DEROctetString(gender.getBytes()))));

            SubjectDirectoryAttributes subjectDirectoryAttributes = new SubjectDirectoryAttributes(attributes);
            try {
                cb.addExtension(X509Extensions.SubjectDirectoryAttributes, isCritical, subjectDirectoryAttributes);
            } catch (CertIOException e) {
                e.printStackTrace();
            }
        }

        //end subject directory attributes

        AlgorithmIdentifier cryptoalg = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
        AlgorithmIdentifier hashalg = new DefaultDigestAlgorithmIdentifierFinder().find(cryptoalg);

        AsymmetricKeyParameter akp = null;
        try {
            akp = PrivateKeyFactory.createKey(keyStore.getKey(keypair_name, null).getEncoded());
            //AsymmetricKeyParameter akp = PrivateKeyFactory.createKey(kp.getPrivate().getEncoded());

            ContentSigner signer = new JcaContentSignerBuilder(algorithm).build((PrivateKey) keyStore.getKey(keypair_name, null));

            //ContentSigner signer = new BcECContentSignerBuilder(cryptoalg, hashalg).build(akp);

            X509CertificateHolder ch = cb.build(signer);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(ch.getEncoded());
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);

            //ovde je gotovo generisanje sertifikata, sad to treba potpisati digitalnim potpisom CA


            Certificate[] ca_certchain = keyStore.getCertificateChain(keypair_name);

            CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();


            PrivateKey capk = (PrivateKey) keyStore.getKey(keypair_name, null);
            //ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(capk);
            //cmsSignedDataGenerator.addSignerInfoGenerator();
            cmsSignedDataGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer, (X509Certificate) keyStore.getCertificate(keypair_name)));

            cmsSignedDataGenerator.addCertificate(ch);
            for (Certificate currentCert : ca_certchain) {
                X509Certificate currentX509Cert = (X509Certificate) currentCert;
                X509CertificateHolder currentCertHolder = new X509CertificateHolder(currentX509Cert.getEncoded());
                cmsSignedDataGenerator.addCertificate(currentCertHolder);
            }

            CMSTypedData content = new CMSProcessableByteArray(cert.getEncoded());
            CMSSignedData signeddata = cmsSignedDataGenerator.generate(content, true);

            FileOutputStream fops = new FileOutputStream(f);

            fops.write("-----BEGIN PKCS #7 SIGNED DATA-----\n".getBytes("ISO-8859-1"));
            fops.write(Base64.getEncoder().encode(signeddata.getEncoded()));
            fops.write("\n-----END PKCS #7 SIGNED DATA-----\n".getBytes("ISO-8859-1"));
            fops.close();
            return true;

        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (CMSException e) {
            e.printStackTrace();
        }


        return false;
    }

    @Override
    public boolean importCAReply(String file, String keypair_name) {

        File f = new File(file);
        try {

            //CMSSignedData

            FileInputStream fips = new FileInputStream(f);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Iterator i = cf.generateCertificates(fips).iterator();
            ArrayList<Certificate> loadedCertificates = new ArrayList<>();


            while (i.hasNext()) {
                Certificate c = (Certificate) i.next();
                loadedCertificates.add(c);
                X509Certificate x509Certificate = (X509Certificate) c;

                System.out.println(new JcaX509CertificateHolder(x509Certificate).getSubject());
                System.out.println(new JcaX509CertificateHolder(x509Certificate).getIssuer());
                //System.out.println(c.toString());
                // TODO encode c as Base64...

            }

            //System.out.println();
            //TODO provera da li je njegov i da li je ok lanac


            Certificate[] chain = new Certificate[loadedCertificates.size()];

            int j = 0;
            for (Certificate curcer : loadedCertificates) {
                chain[j++] = curcer;
            }

            String s1 = ((X509Certificate) chain[0]).getSubjectDN().toString();
            String s2 = ((X509Certificate) keyStore.getCertificate(keypair_name)).getSubjectDN().toString();
            if (!s1.equals(s2)) {
                GuiV3.reportError("Ovaj CA reply nije za vas!");
                return false;
            }
            PrivateKey pr = (PrivateKey) keyStore.getKey(keypair_name, null);
            keyStore.deleteEntry(keypair_name);

            keyStore.setKeyEntry(keypair_name, pr, null, chain);
            saveKeystore();
            loadKeypair(keypair_name);

            return true;


        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }


        return false;
    }

    @Override
    public boolean canSign(String s) {

        try {
            return checkIfIsCertificateAuthority((X509Certificate) keyStore.getCertificate(s));
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public String getSubjectInfo(String s) {

        X509Certificate cert = null;
        try {
            cert = (X509Certificate) keyStore.getCertificate(s);
            //X500Principal subjectData = cert.getSubjectX500Principal();
            //setovanje subject info
            X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();// new X500Name(subjectData.getName());
            return correctNameString(x500name.toString());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }


        return null;
    }

    @Override
    public String getCertPublicKeyAlgorithm(String s) {

        try {
            return keyStore.getCertificate(s).getPublicKey().getAlgorithm();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public String getCertPublicKeyParameter(String s) {

        X509Certificate cert = null;
        PublicKey pk = null;

        try {
            cert = (X509Certificate) keyStore.getCertificate(s);
            pk = cert.getPublicKey();
            switch (this.getCertPublicKeyAlgorithm(s)) {
                case "EC":

                    java.security.interfaces.ECPublicKey ecpk = (java.security.interfaces.ECPublicKey) pk;
                    //ECPublicKey ecpk = (ECPublicKey) keyStore.getCertificate(s).getPublicKey();
                    //System.out.println(ecpk.getParams());


                    String toParse = ecpk.getParams().toString();

                    String[] curves = {"prime256v1", "secp256k1", "secp256r1", "secp384r1", "secp521r1", "sect283k1", "sect283r1", "sect409k1", "sect409r1", "sect571k1", "sect571r1", "P-256", "P-384", "P-521", "B-283", "B-409", "B-571"};
                    for (String target : curves) {
                        if (toParse.contains(target)) {
                            return target;
                        }
                    }
                    return null;

                case "DSA":
                    DSAPublicKey dsapk = (DSAPublicKey) pk;

                    return String.valueOf((dsapk.getParams().getP()));

                case "RSA":
                    java.security.interfaces.RSAPublicKey rsapk = (java.security.interfaces.RSAPublicKey) pk;
                    //org.bouncycastle.asn1.pkcs.RSAPublicKey rsapk = (org.bouncycastle.asn1.pkcs.RSAPublicKey) pk;
                    //RSAPublicKeyImpl rsapk = (RSAPublicKeyImpl) pk;

                    return String.valueOf(rsapk.getModulus().bitLength());

            }

        } catch (KeyStoreException e) {
            e.printStackTrace();
        }


        return null;
    }
}
