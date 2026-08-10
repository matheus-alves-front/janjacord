package br.janjacord.crypto

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import uniffi.janjacord_mobile.*

/**
 * Expõe as funções MLS (UniFFI → libjanjacord_mobile.so) ao JavaScript do React Native.
 * Todas as operações recebem seed_hex (do vault) e retornam strings JSON/base64.
 */
class JanjacordCryptoModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName() = "JanjacordCrypto"

    private fun safe(promise: Promise, fn: () -> String?) {
        try { promise.resolve(fn()) } catch (e: MlsException) { promise.reject("MLS_ERROR", e.message) }
    }

    @ReactMethod fun generateKeyPackage(seedHex: String, identityId: String, promise: Promise) =
        safe(promise) { generateKeyPackage(seedHex, identityId) }

    @ReactMethod fun createGroup(seedHex: String, identityId: String, groupIdHex: String, promise: Promise) =
        safe(promise) { createGroup(seedHex, identityId, groupIdHex) }

    @ReactMethod fun importGroup(identityId: String, groupIdHex: String, stateB64: String, promise: Promise) =
        safe(promise) { importGroup(identityId, groupIdHex, stateB64); null }

    @ReactMethod fun exportGroup(identityId: String, groupIdHex: String, promise: Promise) =
        safe(promise) { exportGroup(identityId, groupIdHex) }

    @ReactMethod fun addMember(seedHex: String, identityId: String, groupIdHex: String, keyPackageB64: String, promise: Promise) =
        safe(promise) { addMember(seedHex, identityId, groupIdHex, keyPackageB64) }

    @ReactMethod fun removeMember(seedHex: String, identityId: String, groupIdHex: String, leafIndex: Int, promise: Promise) =
        safe(promise) { removeMember(seedHex, identityId, groupIdHex, leafIndex) }

    @ReactMethod fun processCommit(seedHex: String, identityId: String, groupIdHex: String, commitB64: String, promise: Promise) =
        safe(promise) { processCommit(seedHex, identityId, groupIdHex, commitB64); null }

    @ReactMethod fun joinGroup(seedHex: String, identityId: String, welcomeB64: String, promise: Promise) =
        safe(promise) { joinGroup(seedHex, identityId, welcomeB64) }

    @ReactMethod fun encrypt(seedHex: String, identityId: String, groupIdHex: String, plaintextB64: String, promise: Promise) =
        safe(promise) { encrypt(seedHex, identityId, groupIdHex, plaintextB64) }

    @ReactMethod fun decrypt(seedHex: String, identityId: String, groupIdHex: String, ciphertextB64: String, promise: Promise) =
        safe(promise) { decrypt(seedHex, identityId, groupIdHex, ciphertextB64) }
}
