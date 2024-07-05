## Certificate Signing Request (CSR) signing using AWS KMS

This program creates a Certificate Signing Request (CSR) signed by an asymmetric key in AWS KMS. 

Please update `<project-root>/cfg/kmscsr.json` config file with your parameters before running this program.
You'll provide AWS KMS asymmetric key ARN, AWS key spec (signing algorithm) name, and certificate common 
name in the config file.

This program has been tested for AWS KMS key spec ECC_NIST_P256 (signing algorithm ECDSA_SHA_256). 
You may extend the program for other signing algorithms. This program uses BouncyCastle library as 
Java Cryptographic Extension (JCE) security provider. It uses the library's `BasicConstraints` extension 
for CSR generation. 

## Instructions

1. Ensure that you have set up AWS credentials as per AWS SDK for Java documentation:
   https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/credentials.html


2. The credentials used should have permissions to invoke KMS Sign API. Please see KMS IAM policy examples below:
   https://docs.aws.amazon.com/kms/latest/developerguide/customer-managed-policies.html


3. Make sure that Maven is installed on your system. Maven needs JDK installed as a prerequisite. You can install
   maven by following the instructions here:
   https://maven.apache.org/install.html


4. Update <project-root>/cfg/kmscsr.json config file with AWS KMS Key ARN, AWS Key Spec and Cert Common Name.
   This program has been tested for AWS KMS key spec ECC_NIST_P256 (signing algorithm ECDSA_SHA_256) and thus
   only supports that key spec in the configuration. You may extend the program for other signing algorithms.
   The program inputs certificate common name (CN) as CSR input parameter. You may extend the program for other
   input parameters such as subject alt names (SANs). Please ensure that the CN you enter in `cert_common_name`
   field in `kmscsr.json` is formatted correctly as per https://www.rfc-editor.org/rfc/rfc1779.html#section-2.3


5. Run this program in the directory where the git repo is cloned by issuing the following command:

   `mvn clean && mvn compile && mvn exec:java`

    The above command will build and execute the code. The program will output the progress of various steps involved 
    and will output a PEM formatted CSR in the end. You may copy/paste the program output in a local file, say
    awskms.csr.


6. You may inspect the CSR contents with OpenSSL by issuing the following command:

   `openssl req -text -noout -verify -in ./awskms.csr`

   You'll see an ouptput such as the following:

   ```
   Certificate request self-signature verify OK
   Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = examplecorp.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:d9:..
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        Attributes:
            Requested Extensions:
                X509v3 Basic Constraints: 
                    CA:FALSE
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:..
   
   ```



## License

This library is licensed under the MIT-0 License. See the LICENSE file.
