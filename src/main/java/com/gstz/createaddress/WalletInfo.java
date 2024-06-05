package com.gstz.createaddress;

import lombok.Data;

/**
 * Description: 
 * Author: songw
 * Date: 2024/6/5 16:57
 */

@Data
public class WalletInfo {

  String mnemonic;
  String password;
  String pubKey;
  String prikey;

}
