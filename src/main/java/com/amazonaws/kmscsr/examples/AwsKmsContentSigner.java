// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

package com.amazonaws.kmscsr.examples;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.SignRequest;

public class AwsKmsContentSigner implements ContentSigner {

    private final String signingAlgorithm;
    private final ByteArrayOutputStream outputStream;
    private final KmsClient awsKmsClient;
    private final String awsKmsKeyId;

    AwsKmsContentSigner(final String inputSigningAlgorithm, final KmsClient inputAwsKmsClient,
            final String inputAwsKmsKeyId) {
        awsKmsClient = inputAwsKmsClient;
        awsKmsKeyId = inputAwsKmsKeyId;
        signingAlgorithm = inputSigningAlgorithm;
        outputStream = new ByteArrayOutputStream();
    }

    private static AlgorithmIdentifier findAlgorithmIdentifier(final String signingAlgorithm) {
        final SignatureAlgorithmIdentifierFinder algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder();
        switch (signingAlgorithm) {
            // This program has been tested for ECDSA_SHA_256 signing algorithm. You may add other algorithms as per:
            // https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html
            case "ECDSA_SHA_256":
                return algorithmIdentifier.find("SHA256WITHECDSA");

            default:
                System.out.println("Signing Algorithm " + signingAlgorithm + " is not supported. Exiting ...");
                System.exit(-1);
                return null;
        }
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return findAlgorithmIdentifier(signingAlgorithm);
    }

    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        // Sign CSR with AWS KMS asymmetric key and extract signature
        final ByteBuffer message = ByteBuffer.wrap(outputStream.toByteArray());
        final SdkBytes sdkBytes = SdkBytes.fromByteBuffer(message);

        final SignRequest signingRequest = SignRequest.builder().keyId(awsKmsKeyId).signingAlgorithm(signingAlgorithm)
                .message(sdkBytes).build();
        System.out.println("Signing request: " + signingRequest);

        System.out.println("Calling Sign() API on AWS KMS ...");
        return awsKmsClient.sign(signingRequest).signature().asByteArray();
    }

}
