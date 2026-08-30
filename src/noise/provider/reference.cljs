(ns noise.provider.reference
  "ClojureScript provider that routes AEAD through first-party
  `chacha20.aead` while keeping X25519 and hash on `provider/noble`.

  This is the **correctness / CI** path for `@noble/ciphers` substitution
  (ADR-2608301100): portable cipher + explicit provider, not deleting
  `@noble/ciphers` from package.json on hot paths. Production handshakes
  should keep `provider/node` or `provider/noble` for speed — see
  `provider/node` docstring for measured costs."
  (:require [chacha20.aead :as aead]
            [noise.provider.noble :as noble]))

(defn aead-encrypt [k nonce ad plaintext]
  (aead/seal! k nonce ad plaintext))

(defn aead-decrypt [k nonce ad ciphertext]
  (let [r (aead/open k nonce ad ciphertext)]
    (when (= :ok (:status r)) (:bytes r))))

(defn ports
  ([] (ports {}))
  ([opts]
   (let [base (noble/ports opts)]
     (assoc base
            :aead-encrypt aead-encrypt
            :aead-decrypt aead-decrypt))))
