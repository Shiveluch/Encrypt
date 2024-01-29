package com.shiveluch.encrypt
import android.content.Context
import android.content.SharedPreferences
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import android.util.Base64
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class RSA(private val context: Context) {

  private val sharedPreferences: SharedPreferences by lazy {
    context.getSharedPreferences("keyPrefs", Context.MODE_PRIVATE)
  }

  companion object {
    private const val ALGORITHM = "RSA"
    private const val KEY_SIZE = 2048
    private const val TRANSFORMATION = "RSA/ECB/PKCS1Padding"
    private const val PUBLIC_KEY = "public_key"
    private const val PRIVATE_KEY = "private_key"
    fun encrypt(data: ByteArray, publicKey: PublicKey): ByteArray {
      val cipher = Cipher.getInstance(TRANSFORMATION)
      cipher.init(Cipher.ENCRYPT_MODE, publicKey)
      return cipher.doFinal(data)
    }

    fun decrypt(data: ByteArray, privateKey: PrivateKey): ByteArray {
      val cipher = Cipher.getInstance(TRANSFORMATION)
      cipher.init(Cipher.DECRYPT_MODE, privateKey)
      return cipher.doFinal(data)
    }

  }
    fun generateKeyPair() {
      val keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM)
      keyPairGenerator.initialize(KEY_SIZE)
      val keyPair = keyPairGenerator.generateKeyPair()
      val publicKeyString = Base64.encodeToString(keyPair.public.encoded, Base64.DEFAULT)
      val privateKeyString = Base64.encodeToString(keyPair.private.encoded, Base64.DEFAULT)
      saveKeysToPreferences(PUBLIC_KEY, publicKeyString)
      saveKeysToPreferences(PRIVATE_KEY, privateKeyString)
    }

    private fun saveKeysToPreferences(key: String, value: String) {
      sharedPreferences.edit().putString(key, value).apply()
    }

  fun getPublicKey(): String? {
    return sharedPreferences.getString(PUBLIC_KEY, null)
  }

  fun getPrivateKey(): String? {
    return sharedPreferences.getString(PRIVATE_KEY, null)
  }

  fun stringToPublicKey(publicKeyString: String): PublicKey {
    val keyFactory = KeyFactory.getInstance("RSA")
    val keyBytes = Base64.decode(publicKeyString,0);
    val keySpec = X509EncodedKeySpec(keyBytes)
    return keyFactory.generatePublic(keySpec)
  }

  fun stringToPrivateKey(publicKeyString: String): PrivateKey {
    val keyFactory = KeyFactory.getInstance("RSA")
    val keyBytes = Base64.decode(publicKeyString,0);
    val keySpec = PKCS8EncodedKeySpec(keyBytes)
    return keyFactory.generatePrivate(keySpec)
  }
}

