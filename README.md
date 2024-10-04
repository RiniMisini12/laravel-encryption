# Laravel Encryption

A Go package that provides encryption and decryption for strings and arrays identical to Laravel's Encrypter. This package is perfect for securely sharing encrypted data between Go applications and Laravel backends.

## Features

- Encrypt and decrypt strings in a way that is fully compatible with Laravel's encryption.
- Encrypt and decrypt arrays (or any serializable data) using Laravel's encryption format.
- Avoids "MAC is invalid" or "invalid payload" errors by ensuring compatibility with Laravel's encryption key format.

## Installation

To install the package, simply run:

```bash
go get github.com/RiniMisini12/laravel-encryption
```

### Usage

1. **Full Laravel App Key Required**  
   To use this package, you will need the full `APP_KEY` from your Laravel application's `.env` file. The key should be in `base64` format, and you can pass it directly to the functions provided by this package.

2. **Encryption and Decryption of Strings**

   **Encrypting a String**  
   You can encrypt a string by using the `EncryptString` function and passing the string along with your Laravel `APP_KEY`:

   ```go
   package main

    import (
        "fmt"
        "log"
        "github.com/yourusername/laravel-encryption"
    )

    func main() {
        appKey := "base64:YOUR_APP_KEY"

        encryptedString, err := encrypter.EncryptString("My secret data", appKey)
        if err != nil {
            log.Fatalf("Error encrypting string: %v", err)
        }

        fmt.Println("Encrypted string:", encryptedString)
    }
   ```

   **Decrypting a String**  
   To decrypt the string, pass the encrypted text and `APP_KEY` to the `DecryptString` function:

    ```go
    package main

    import (
        "fmt"
        "log"
        "github.com/yourusername/laravel-encryption"
    )

    func main() {
        appKey := "base64:YOUR_APP_KEY"
        encryptedString := "ENCRYPTED_TEXT_HERE"

        decryptedString, err := encrypter.DecryptString(encryptedString, appKey)
        if err != nil {
            log.Fatalf("Error decrypting string: %v", err)
        }

        fmt.Println("Decrypted string:", decryptedString)
    }
    ```

3. **Encryption and Decryption of Arrays**

   **Encrypting an Array**
   You can encrypt arrays (or any serializable data) by passing them to the `EncryptArray` function:

    ```go
    package main

    import (
        "fmt"
        "log"
        "github.com/yourusername/laravel-encryption"
    )

    func main() {
        appKey := "base64:YOUR_APP_KEY"
        arrayToBeEncrypted := []string{"item1", "item2", "item3"}

        encryptedArray, err := encrypter.EncryptArray(arrayToBeEncrypted, appKey)
        if err != nil {
            log.Fatalf("Error encrypting array: %v", err)
        }

        fmt.Println("Encrypted array:", encryptedArray)
    }
    ```

    **Decrypting an Array**
    To decrypt an encrypted array, use the `DecryptArray` function:

    ```go
    package main

    import (
        "fmt"
        "log"
        "github.com/yourusername/laravel-encryption"
    )

    func main() {
        appKey := "base64:YOUR_APP_KEY"
        encryptedArray := "ENCRYPTED_ARRAY_HERE"

        decryptedArray, err := encrypter.DecryptArray(encryptedArray, appKey)
        if err != nil {
            log.Fatalf("Error decrypting array: %v", err)
        }

        fmt.Println("Decrypted array:", decryptedArray)
    }
    ```

4. **Laravel Compatibility**
    This package ensures full compatibility with Laravel’s encryption. It follows the same process as Laravel for:

    - Encryption: `AES-256-CBC` encryption with `HMAC` for integrity verification.
    - Decryption: Ensures that the data is decrypted only if the `HMAC` is valid.
    - Note: The Laravel `APP_KEY` must be passed in full, including the base64: prefix.

    This project is licensed under the [MIT License](./LICENSE). See the [LICENSE](./LICENSE) file for details.

