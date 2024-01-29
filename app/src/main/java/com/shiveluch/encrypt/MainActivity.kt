package com.shiveluch.encrypt

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import java.security.KeyPair
class MainActivity : AppCompatActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        encDec("Хаба хаба рулез");
    }
 fun encDec(data:String) {
   val rsa = RSA(applicationContext)
   var publicKeyString = rsa.getPublicKey()
   var privateKeyString = rsa.getPrivateKey()

   if (publicKeyString==null||privateKeyString==null) {
     rsa.generateKeyPair()
      publicKeyString = rsa.getPublicKey()
      privateKeyString = rsa.getPrivateKey()
   }
    val keyPair = KeyPair(publicKeyString?.let { rsa.stringToPublicKey(it) },privateKeyString?.let { rsa.stringToPrivateKey(it) })
    val sendData = data.toByteArray()
    val encryptedData = RSA.encrypt(sendData, keyPair.public)
    val decryptedData = RSA.decrypt(encryptedData, keyPair.private)
    Log.d("RSA", "KEY: ${keyPair.public}")
    Log.d("RSA","Encrypted Data (Base64): ${encryptedData.joinToString(",")}")
    Log.d("RSA","Decrypted Data: ${String(decryptedData)}")
  }
}