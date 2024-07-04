// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

package com.amazonaws.kmscsr.examples;

import com.google.gson.annotations.SerializedName;

public class Config {

    @SerializedName("aws_key_spec")
    private String awsKeySpec;

    @SerializedName("aws_key_arn")
    private String awsKeyArn;

    @SerializedName("cert_common_name")
    private String certCommonName;

    public String getAwsKeySpec() {
        return awsKeySpec;
    }

    public String getAwsKeyArn() {
        return awsKeyArn;
    }

    public String getCertCommonName() {
        return certCommonName;
    }

}