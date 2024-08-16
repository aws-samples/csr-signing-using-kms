// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

package com.amazonaws.kmscsr.examples;

import java.io.IOException;
import java.util.Base64;

import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

public class GenerateCDPSample {

    public static void main(final String[] args) throws IOException {
        String crlUrl;
        crlUrl = "http://example.com/crl/0116z123-dv7a-59b1-x7be-1231v72571136.crl";
        CRLDistPoint crlDistributionPoint = new CRLDistPoint(new DistributionPoint[] {
            new DistributionPoint(
                    new DistributionPointName(new GeneralNames(new GeneralName(
                            GeneralName.uniformResourceIdentifier,
                            crlUrl))),
                    null,
                    null)
        });
        System.out.println(Base64.getEncoder().encodeToString(crlDistributionPoint.getEncoded()));
    }
}