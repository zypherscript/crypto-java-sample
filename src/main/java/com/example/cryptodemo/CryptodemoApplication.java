package com.example.cryptodemo;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

@SpringBootApplication
public class CryptodemoApplication {

  public static void main(String[] args) {
    SpringApplication.run(CryptodemoApplication.class, args);
  }

  @Bean
  CommandLineRunner runner(HashingDemo hashingDemo,
      SymmetricEncryptionDemo symmetricEncryptionDemo,
      AsymmetricEncryptionDemo asymmetricEncryptionDemo,
      DigitalSignatureWithAsymmetricEncryptionDemo digitalSignatureWithAsymmetricEncryptionDemo,
      KeyStoreGeneratorDemo keyStoreGeneratorDemo) {
    return args -> {
      var random = new SecureRandom();
      var salt = new byte[16];
      random.nextBytes(salt);

      hashingDemo.hashText("sheesh", salt); //one way only
      hashingDemo.hashText("sheesh", salt); //deterministic
      hashingDemo.hashText("she3sh", salt); //pseudorandom
      hashingDemo.hashText("sheeeeeeeeeeeeeesh", salt); //fixed length

      symmetricEncryptionDemo.symmetricEncrypt();
      asymmetricEncryptionDemo.asymmetricEncrypt();
      digitalSignatureWithAsymmetricEncryptionDemo.digitalSignatureWithAsymmetricEncrypt();

      keyStoreGeneratorDemo.createKeyStore();
    };
  }
}

@UtilityClass
@Slf4j
class Utils {

  static String convertBytes(byte[] bytes) {
    var sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  static String decodeBytes(byte[] bytes) {
    var hexString = convertBytes(bytes);
    var decodedBytes = new byte[hexString.length() / 2];

    for (int i = 0; i < decodedBytes.length; i++) {
      int index = i * 2;
      int j = Integer.parseInt(hexString.substring(index, index + 2), 16);
      decodedBytes[i] = (byte) j;
    }

    return new String(decodedBytes, StandardCharsets.UTF_8);
  }
}

@Component
@Slf4j
class HashingDemo {

  void hashText(String str, byte[] salt) throws NoSuchAlgorithmException {
    var messageDigest = MessageDigest.getInstance("SHA-256");
    messageDigest.update(salt);
    var digest = messageDigest.digest(str.getBytes());
    log.info("Input: " + str);
    log.info("Digest: " + Utils.convertBytes(digest));
  }
}

@Component
@Slf4j
class SymmetricEncryptionDemo {

  public void symmetricEncrypt()
      throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException,
      BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
    var generator = KeyGenerator.getInstance("AES");
    generator.init(192);
    var key = generator.generateKey();

    var input = "Sheesh".repeat(16).getBytes();
    log.info("Input: " + Utils.decodeBytes(input));

    var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    var secureRandom = SecureRandom.getInstance("SHA1PRNG");
    var random = new byte[16];
    secureRandom.nextBytes(random);
    var ivSpec = new IvParameterSpec(random);
    log.info("ivSpec: " + Utils.convertBytes(random));

    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    var encryptedOutput = cipher.doFinal(input);
    log.info("Encrypted Output: " + Utils.convertBytes(encryptedOutput));

    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    var decryptedOutput = cipher.doFinal(encryptedOutput);
    log.info("Decrypted Output: " + Utils.decodeBytes(decryptedOutput));
  }
}

@Component
@Slf4j
class AsymmetricEncryptionDemo {

  public void asymmetricEncrypt()
      throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException,
      BadPaddingException, NoSuchPaddingException {
    //don't use Asymmetric encryption to encrypt large blocks of data
    var kpGen = KeyPairGenerator.getInstance("RSA");
    kpGen.initialize(1024);
    var keyPair = kpGen.generateKeyPair();

    var input = "Sheesh".repeat(6).getBytes();
    log.info("Input: " + Utils.decodeBytes(input));

    var cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
    var encryptedOutput = cipher.doFinal(input);
    log.info("Encrypted Output: " + Utils.convertBytes(encryptedOutput));

    cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
    var decryptedOutput = cipher.doFinal(encryptedOutput);
    log.info("Decrypted Output: " + Utils.decodeBytes(decryptedOutput));
  }
}

@Component
@Slf4j
class DigitalSignatureWithAsymmetricEncryptionDemo {

  public void digitalSignatureWithAsymmetricEncrypt()
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    var kpGen = KeyPairGenerator.getInstance("RSA");
    kpGen.initialize(1024);
    var keyPair = kpGen.generateKeyPair();

    var input = "Sheesh".repeat(6).getBytes();
    log.info("Input: " + Utils.decodeBytes(input));

    var signatureAlgorithm = Signature.getInstance("SHA256WithRSA");
    signatureAlgorithm.initSign(keyPair.getPrivate());
    signatureAlgorithm.update(input);
    var signature = signatureAlgorithm.sign();
    log.info("Signature: " + Utils.convertBytes(signature));

    var verificationAlgorithm = Signature.getInstance("SHA256WithRSA");
    verificationAlgorithm.initVerify(keyPair.getPublic());
    verificationAlgorithm.update(input);

    var matches = verificationAlgorithm.verify(signature);
    log.info("Signature matches: " + matches);
  }
}

@Component
@Slf4j
class KeyStoreGeneratorDemo {

  public void createKeyStore()
      throws GeneralSecurityException, IOException, OperatorCreationException {
    var path = Path.of("myStore.pkcs12");
    if (Files.exists(path)) {
      Files.delete(path);
    }

    // Create a new PKCS12 KeyStore instance & Initialize the empty keystore with null parameters
    var keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, null);

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    var kp = kpg.generateKeyPair();
    var pvt = kp.getPrivate();

    // Generate the root X509 certificate using the generated key pair
    var x509Certificate = generateRootCert(kp);
    keyStore.setCertificateEntry("myRootCertificate", x509Certificate);
    // Create a certificate chain array containing only the root certificate
    Certificate[] chain = {x509Certificate};

    keyStore.setKeyEntry("myPrivateKey", pvt, "password".toCharArray(), chain);
    keyStore.store(new FileOutputStream("myStore.pkcs12"), "password".toCharArray());

    //testing
    var enums = keyStore.aliases();
    log.info("aliases:");
    enums.asIterator().forEachRemaining(System.out::println);

    var key = keyStore.getKey("myPrivateKey", "password".toCharArray());
    log.info(key.toString());

    Certificate certificate = keyStore.getCertificate("myRootCertificate");
    log.info(certificate.toString());
  }

  private X509Certificate generateRootCert(KeyPair pair)
      throws IOException, OperatorCreationException, CertificateException {
    // Create a calendar instance and set the expiry date of the certificate to one year from now
    var expiry = Calendar.getInstance();
    expiry.add(Calendar.DAY_OF_YEAR, 365);

    var algorithmIdentifier = new AlgorithmIdentifier(
        PKCSObjectIdentifiers.sha256WithRSAEncryption);
    var sigAlgId = new AlgorithmIdentifier(algorithmIdentifier.getAlgorithm(), DERNull.INSTANCE);

    final AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(
        sigAlgId);

    final BcContentSignerBuilder signerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
    final AsymmetricKeyParameter keyPrivate = PrivateKeyFactory.createKey(
        pair.getPrivate().getEncoded());
    final ContentSigner signer = signerBuilder.build(keyPrivate);

    var x509v3CertificateBuilder = new X509v3CertificateBuilder(
        new X500Name("CN=Root Certificate"),
        BigInteger.ONE,
        new Date(),
        expiry.getTime(),
        Locale.ENGLISH,
        new X500Name("CN=Root Certificate"),
        SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded())
    );

    final X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(signer);
    return new JcaX509CertificateConverter()
        .getCertificate(x509CertificateHolder);
  }
}
