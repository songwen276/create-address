package com.gstz.createaddress;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import org.web3j.crypto.Bip32ECKeyPair;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.MnemonicUtils;
import org.web3j.utils.Numeric;

public class CreateAddress {

  static String workPath;
  static String separator;
  static String lineSeparator;

  static {
    workPath = System.getProperty("user.dir");
    separator = System.getProperty("file.separator");
    lineSeparator = System.lineSeparator();
  }

  public static void main(String[] args) {
    if (args.length != 2) {
      System.out.println(
          "请传入需要创建钱包的数量及钱包密码，eg：java -jar createeigeninfo-0.0.1-SNAPSHOT-jar-with-dependencies.jar <numberOfWallets> <password>");
      return;
    }

    // 设置要生成的钱包数量
    int numberOfWallets = Integer.parseInt(args[0]);
    // 设置钱包密码
    String password = args[1];
    // 设置保存的目录
    String mnicAndPassWdDir = workPath + separator + "mnicAndPassWd.properties";
    String addrAndPubKeyDir = workPath + separator + "addrAndPubKey.properties";
    String addrAndPriKeyDir = workPath + separator + "addrAndPriKey.properties";

    // 生成助记词
    byte[] entropy = new byte[16];
    SecureRandom secureRandom = new SecureRandom();
    secureRandom.nextBytes(entropy);
    String mnemonic = MnemonicUtils.generateMnemonic(entropy);

    // 使用助记词生成种子
    byte[] seed = MnemonicUtils.generateSeed(mnemonic, "");

    // 使用种子生成根密钥对并打印
    Bip32ECKeyPair rootKeyPair = Bip32ECKeyPair.generateKeyPair(seed);
    String rootPubKey = Numeric.toHexStringNoPrefix(rootKeyPair.getPublicKey());
    String rootPrikey = Numeric.toHexStringNoPrefix(rootKeyPair.getPrivateKey());
    System.out.println("Root public key: " + rootPubKey);
    System.out.println("Root private key: " + rootPrikey);

    List<String> mnicAndPassWdInfos = new ArrayList<>();
    String mnicAndPassInfo = "助记词："+mnemonic + lineSeparator +
                             "密码："+password + lineSeparator +
                             "根公钥："+rootPubKey + lineSeparator +
                             "根私钥："+rootPrikey;
    mnicAndPassWdInfos.add(mnicAndPassInfo);
    System.out.println("当前批次所有钱包的助记词，密码，根密钥对的公私密钥为：" + lineSeparator + mnicAndPassInfo);

    List<String> addrAndPriKeyInfos = new ArrayList<>();
    List<String> addrAndPubKeyInfos = new ArrayList<>();

    // 定义 BIP-44 路径的通用部分：m/44'/60'/0'/0/
    int[] commonPath = {44 | Bip32ECKeyPair.HARDENED_BIT, 60 | Bip32ECKeyPair.HARDENED_BIT,
        Bip32ECKeyPair.HARDENED_BIT, 0};

    try {
      for (int i = 0; i < numberOfWallets; i++) {
        // 构造派生path
        int[] path = new int[commonPath.length + 1];
        System.arraycopy(commonPath, 0, path, 0, commonPath.length);
        path[commonPath.length] = i;

        // 派生子密钥
        Bip32ECKeyPair derivedKeyPair = Bip32ECKeyPair.deriveKeyPair(rootKeyPair, path);
        String publicKey = Numeric.toHexStringNoPrefix(derivedKeyPair.getPublicKey());
        String privateKey = Numeric.toHexStringNoPrefix(derivedKeyPair.getPrivateKey());

        // 根据密钥生成子账号信息
        Credentials credentials = Credentials.create(derivedKeyPair);
        String walletAddress = credentials.getAddress();
        System.out.println("Address " + i + ": " + walletAddress);
        String pubInfo = walletAddress + "=" + publicKey;
        String priInfo = walletAddress + "=" + privateKey;
        addrAndPubKeyInfos.add(pubInfo);
        addrAndPriKeyInfos.add(priInfo);
        System.out.println(pubInfo);
        System.out.println(priInfo);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    saveToFile(mnicAndPassWdInfos, mnicAndPassWdDir);
    saveToFile(addrAndPubKeyInfos, addrAndPubKeyDir);
    saveToFile(addrAndPriKeyInfos, addrAndPriKeyDir);
  }

  private static void saveToFile(List<String> data, String fileName) {
    try (BufferedWriter writer = new BufferedWriter(
        new OutputStreamWriter(Files.newOutputStream(Paths.get(fileName)), StandardCharsets.UTF_8))) {
      for (String line : data) {
        writer.write(line + System.lineSeparator());
      }
      System.out.println("输出到文件成功：路径为：" + fileName);
    } catch (IOException e) {
      e.printStackTrace();
      System.out.println("输出到文件异常：" + fileName);
    }
  }

}
