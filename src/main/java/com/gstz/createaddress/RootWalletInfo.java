package com.gstz.createaddress;

import java.util.List;
import lombok.Data;

/**
 * Description: 
 * Author: songw
 * Date: 2024/6/5 16:57
 */

@Data
public class RootWalletInfo {

  String rootMnemonic;
  String rootPassword;
  String rootPubKey;
  String rootPrikey;
  List<WalletInfo> subWalletInfos;

}
