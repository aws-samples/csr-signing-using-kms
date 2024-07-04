// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

package com.amazonaws.kmscsr.examples;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.endpoints.internal.Arn;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CsrCreator {

    private KmsClient awsKmsClient;
    private String keyId;
    private byte[] publicKeyBytes;
    private String kmsRegion;
    private String jceSigningAlgorithm;
    private String certCommonName;
    private String signingAlgorithm;
    private String awsKeySpec;

    public CsrCreator() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(final String[] args) throws Exception {
        System.out.println("Running CSR creation and signing using AWS KMS util ... ");

        final CsrCreator csrCreator = new CsrCreator();
        csrCreator.readConfig();
        csrCreator.fetchAwsKmsPublicKey();
        final String pemFormattedCsr = csrCreator.createAndSignCsr();
        System.out.println("PEM formatted CSR:\n" + pemFormattedCsr);

        csrCreator.awsKmsClient.close();
        System.exit(0);
    }

    /**
     * Returns a JCE compliance signing algorithm name given an AWS KMS key spec.
     * https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keyfactory-algorithms
     */
    private static String getJceKeyFactoryAlgorithmName(final String signingAlgorithm) {
        // This code has been tested for Elliptic Curve algorithm. You may extend it for additional algorithms.
        if (signingAlgorithm.startsWith("EC")) {
            return "EC";
        }

        String errMsg = "Signing Algorithm " + signingAlgorithm + " is not supported. " +
                "Pls. see README for supported signing algorithms";
        throw new IllegalArgumentException(errMsg);
    }

    /**
     * Reads config file <project-root>/cfg/kmscsr.json
     */
    private void readConfig() {
        final String userDir = System.getProperty("user.dir");
        System.out.println("Project Directory: " + userDir);
        final String cfgFilePathName = userDir + "/cfg/kmscsr.json";

        System.out.println("Reading config file: " + cfgFilePathName);
        String cfgJsonString = null;

        try {
            cfgJsonString = new String(Files.readAllBytes(Paths.get(cfgFilePathName)), StandardCharsets.UTF_8);
        } catch (IOException e) {
            System.out.println("ERROR: Error reading config file kmscsr.json.\n" +
                    "Please ensure that the file is present under <project-root>/cfg/kmscsr.json. Exiting ...");
            e.printStackTrace();
            System.exit(-1);
        }

        System.out.println("Found config file " + cfgFilePathName);
        System.out.println("Read config contents " + cfgJsonString);

        final Gson gson = new Gson();
        Config cfgJsonObj = null;
        try {
            cfgJsonObj = gson.fromJson(cfgJsonString, Config.class);
        } catch (JsonSyntaxException e) {
            System.out.println("ERROR: Invalid JSON syntax in <project-root>/cfg/kmscsr.json. Exiting ...\n");
            System.exit(-1);
        }

        // Extract signing algorithm from config
        System.out.println("Extracting parameters from config file ...");

        awsKeySpec = cfgJsonObj.getAwsKeySpec();
        System.out.println("AWS Key Spec: " + awsKeySpec);

        signingAlgorithm = getSigningAlgorithmFromAwsKeySpec(awsKeySpec);
        System.out.println("Signing algorithm: " + signingAlgorithm);

        jceSigningAlgorithm = getJceKeyFactoryAlgorithmName(signingAlgorithm);
        System.out.println("JCE compliant signing algorithm: " + jceSigningAlgorithm);

        // Extract Key Id and region from Key ARN read from config
        // Key ARN format: "arn:aws:kms:us-east-1:012345678901:key/some-key-id"
        final Optional<Arn> awsKmsKeyArn = Arn.parse(cfgJsonObj.getAwsKeyArn());
        if (!awsKmsKeyArn.isPresent()) {
            System.out.println("ERROR: Key ARN provided in config could not be parsed: " + cfgJsonObj.getAwsKeyArn());
            System.out.println("Fix configuration. Exiting ...");
            System.exit(-1);
        }

        kmsRegion = awsKmsKeyArn.get().region();
        System.out.println("AWS KMS Region: " + kmsRegion);

        // For key ARN example:
        // "arn:aws:kms:your-aws-region:012345678901:key/123456-1234-1234-1234-1234567890",
        // The Arn object resource() list is returned as: [key, 123456-1234-1234-1234-1234567890]
        final List<String> resourceList = awsKmsKeyArn.get().resource();
        keyId = resourceList.get(1); // Second item in list contains keyId
        System.out.println("AWS KMS Key Id: " + keyId);

        // Extract CSR input fields from config
        certCommonName = cfgJsonObj.getCertCommonName();
        System.out.println("Cert Common Name: " + certCommonName);

        // Basic syntax checking of CN for brevity: Value should not contain separators and equal(=) sign
        // Formal CN syntax is defined in: https://www.rfc-editor.org/rfc/rfc1779.html#section-2.3
        Pattern cnRegexValidationattern = Pattern.compile(",|;|=");
        Matcher cnRegexMatcher = cnRegexValidationattern.matcher(certCommonName);
        if (cnRegexMatcher.find()) {
            System.out.println("ERROR: cert_common_name in kmscsr.json contains illegal characters " + certCommonName);
            System.out.println("Fix configuration. Exiting ...");
            System.exit(-1);
        }
    }

    /**
     * Issues a call to AWS KMS to fetch public key associated with key ARN provided in config.
     */
    private void fetchAwsKmsPublicKey() {
        System.out.println("Fetching public key from AWS KMS ...");
        awsKmsClient = KmsClient.builder().region(Region.of(kmsRegion)).build();
        final GetPublicKeyRequest getPublicKeyRequest = GetPublicKeyRequest.builder().keyId(keyId).build();
        final SdkBytes publicKeySdkBytes = awsKmsClient.getPublicKey(getPublicKeyRequest).publicKey();
        publicKeyBytes = publicKeySdkBytes.asByteArray();
    }

    /**
     * Returns signing algorithm corresponding to input AWS key spec
     */
    private String getSigningAlgorithmFromAwsKeySpec(final String awsKeySpec) {
        // The AWS key spec string names below are derived from AWS documentation:
        // https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html
        switch (awsKeySpec) {
            case "ECC_NIST_P256":
                return "ECDSA_SHA_256";

            default:
                throw new IllegalArgumentException("AWS Key Spec " + awsKeySpec + " is not supported");
        }
    }

    /**
     * Creates a CSR object and gets it signed by AWS KMS asymmetric key.
     */
    private String createAndSignCsr() {
        // Encode public key bytes to ASN.1 and generate a JCE compliant PublicKey object
        System.out.println("Encoding public key in ASN.1 format ...");
        final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = null;
        try {
            publicKey = KeyFactory.getInstance(jceSigningAlgorithm, BouncyCastleProvider.PROVIDER_NAME)
                    .generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Key spec provided in config is invalid", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Signing algorithm (part of key spec) provided in config is invalid", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Internal program error. Try rebuilding program", e);
        }

        System.out.println("Creating CSR ...");
        X500Name csrSubject = new X500Name("CN=" + certCommonName);
        JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(csrSubject,
                publicKey);
        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        try {
            extensionsGenerator.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        } catch (IOException e) {
            System.out.println("ERROR: Potential error in certificate common name in config. Exiting ...");
            e.printStackTrace();
            System.exit(-1);
        }
        csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());

        System.out.println("Signing CSR using AWS KMS ...");
        PKCS10CertificationRequest csr = csrBuilder
                .build(new AwsKmsContentSigner(signingAlgorithm, awsKmsClient, keyId));

        System.out.println("Converting CSR to PEM format ...");
        PemObjectGenerator miscPEMGenerator = new MiscPEMGenerator(csr);
        StringWriter csrStringWriter = new StringWriter();

        try (PemWriter csrPemWriter = new PemWriter(csrStringWriter)) {
            csrPemWriter.writeObject(miscPEMGenerator);
        } catch (IOException e) {
            System.out.println("ERROR: Internal program error in PEM formatting. Exiting ...");
            e.printStackTrace();
            System.exit(-1);
        }

        return csrStringWriter.toString();
    }
}