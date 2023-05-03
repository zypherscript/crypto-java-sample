package com.example.cryptodemo;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class CryptodemoApplication {

  public static void main(String[] args) {
    SpringApplication.run(CryptodemoApplication.class, args);
  }

  @Bean
  CommandLineRunner runner() {
    return args -> {
      var random = new SecureRandom();
      var salt = new byte[16];
      random.nextBytes(salt);

      HashingDemo.hashText("sheesh", salt); //one way only
      HashingDemo.hashText("sheesh", salt); //deterministic
      HashingDemo.hashText("she3sh", salt); //pseudorandom
      HashingDemo.hashText("sheeeeeeeeeeeeeesh", salt); //fixed length
    };
  }
}

@UtilityClass
@Slf4j
class HashingDemo {

  private String convertBytes(byte[] digest) {
    var sb = new StringBuilder();
    for (byte b : digest) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  static void hashText(String str, byte[] salt) throws NoSuchAlgorithmException {
    var messageDigest = MessageDigest.getInstance("SHA-256");
    messageDigest.update(salt);
    var digest = messageDigest.digest(str.getBytes());
    log.info("Input: " + str);
    log.info("Digest: " + convertBytes(digest));
  }
}
