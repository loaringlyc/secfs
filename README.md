# A Secure File Sharing System

### Introduction

For comprehensive documentation, see the cs161 Project 2 Spec (https://cs161.org/proj2/).

```
secfs/
├── client/                    # main package
│   ├── client.go              # core logics
│   └── client_unittest.go     # unit test for helper functions
│
├── client_test/               # integrate test
│   └── client_test.go         # Ginkgo style test
│
├── go.mod                     # Go module manage file
├── go.sum                     # Go check file
├── README.md                  
└── .gitignore                
```

### Go Language

To learn about go language, visit the official tutorial https://tour.golang.org/welcome/1. It is worth referencing frequently when learning for the first time.

### Test 

To test the implementation, run `go test -v` inside of the `client_test` directory. This will run all tests in both `client/client_unittest.go` and `client_test/client_test.go`.

The test cases are written using Ginkgo framework. Take `client_test.go` for an example:
- Function `TestSetupAndExecution()` is the entrance function of `go test -v`. 
- Function `RegisterFailHandler` is the bridge between Ginkgo test package and Gomega assertion package
- Function `RunSpecs` starts the testing process

To write a test function, we could mimic the behavious in this file. For example:
```go
// Check that an error didn't occur
alice, err := client.InitUser("alice", "password")
Expect(err).To(BeNil())

// Check that an error didn't occur
err = alice.StoreFile("alice.txt", []byte("hello world"))
Expect(err).To(BeNil())

// Check that an error didn't occur AND that the data is what we expect
data, err := alice.LoadFile("alice.txt")
Expect(err).To(BeNil())
Expect(data).To(Equal([]byte("hello world")))

// Check that an error DID occur
data, err := alice.LoadFile("rubbish.txt")
Expect(err).ToNot(BeNil())
```

### Design Overview

#### Functionality Overview

This project designs a system that allows users to securely store and share files in the presence of attackers. In particular, the following 8 functions will be implemented:

- `InitUser`: Given a new username and password, create a new user.
- `GetUser`: Given a username and password, let the user log in if the password is correct.
- `User.StoreFile`: For a logged-in user, given a filename and file contents, create a new file or overwrite an existing file.
- `User.LoadFile`: For a logged-in user, given a filename, fetch the corresponding file contents.
- `User.AppendToFile`: For a logged-in user, given a filename and additional file contents, append the additional file contents at the end of the existing file contents, while following some efficiency requirements.
- `User.CreateInvitation`: For a logged-in user, given a filename and target user, generate an invitation UUID that the target user can use to gain access to the file.
- `User.AcceptInvitation`: For a logged-in user, given an invitation UUID, obtain access to a file shared by a different user. Allow the recipient user to access the file using a (possibly different) filename of their own choosing.
- `User.RevokeAccess`: For a logged-in user, given a filename and target user, revoke the target user’s access so that they are no longer able to access a shared file.

These 8 functions will be implemented as part of the `User` class. The user class has 2 constructors & 6 instance methods. If a user calls a constructor multiple times, there will be multiple `User` objects that all represent the same user and all the objects should not use **outdated** data. 

All 8 functions have `err` as one of their return values. The function could fail due to functionality issues (e.g. a user supplies an invalid argument), or security issues (e.g. an attacker has tampered with data that prevents your function from executing correctly). 

> [!NOTE]
>
> - There is **no frontend** for this project, and all users need to interact with the system by running a copy of the code.
> - This project implement a **serial** file sharing system, so parallel function calls are not under concern. Also, one function is assumed to be executed after other functions are completed. 

#### Stateless Design

Because users may log in in different devices, our implementation is stateless, which means that global variables & local memory should not be utilized. All devices running your code are able to send and receive data from two shared remote databases called Datastore and Keystore.

**Keystore**:  store public keys. It is organized as a set of name-value pairs, similar to a dictionary in Python or a HashMap in Javame-value . The name in each name-value pair must be string. The value in each napair must be a public key (`PKEEncKey` or `DSVerifyKey`). Note that, the total number of keys on Keystore should only scale with the number of users.

**Datastore**: store any byte data. It is also organized as a set of name-value pairs. The name in each name-value pair must be a UUID, a unique 16-byte string. The value in each name-value pair can be any byte array of data.  

#### Threat Model

The high-level goal is that the users could store their data on an untrusted server. Other users should not be able to access their data, and even if the server is malicious, it should not be able to access their data. 

**Datastore Adversary**: The Datastore Adversary is an attacker who can read and modify all name-value pairs, and add new name-value pairs, on Datastore. It can 1) compare the difference of snapshots to see which name-value pairs changed as a result of the function call; 2) see when a user calls a function; 3) see what the inputs and outputs to the functions that call Datastore APIs are. But it cannot 1) collude with other users; 2) perform any rollback attacks. 

**Revoked User Adversary**: 

### Library Functions

Some cryptographic functions and some utility helper functions have been implemented in https://github.com/cs161-staff/project2-userlib/. 

Note that unsafe cryptographic design patterns such as reusing the same keys in different algorithms, or using MAC-then-encrypt, are avoided.

#### Types

There are several data types in the user library:

- `PKEEncKey`: An RSA public key. Recall that public keys are used to encrypt data.
- `PKEDecKey`: An RSA private key. Recall that private keys are used to decrypt data.
- `DSSignKey`: An RSA signing key. Recall that signing keys are used to create digital signatures.
- `DSVerifyKey`: An RSA verification key. Recall that verification keys are used to verify digital signatures.
- `uuid.UUID`: A UUID created through `uuid.New` or `uuid.FromBytes`, used as a key for the Datastore.
- `[]bytes`: An array of arbitrary bytes. You must turn other types into an array of bytes using `json.Marshal`.

#### Keystore

```go
// Stores a name and value as a name-value pair into Keystore
// 	The name can be any unique string, and the value must be a public key
userlib.KeystoreSet(name string, value PKEEncKey|DSVerifyKey) (err error)

// Looks up the provided name and returns the corresponding value
userlib.KeystoreGet(name string) (value PKEEncKey|DSVerifyKey, ok bool)
```

#### Datastore

```go
// Stores name and value as a name-value pair into Datastore
userlib.DatastoreSet(name uuid.UUID, value []byte)

// Looks up the provided name and returns the corresponding value
// 	If a corresponding value exists, then ok will be true; otherwise, ok will be false
userlib.DatastoreGet(name uuid.UUID) (value []byte, ok bool)

// Looks up the provided name and deletes the corresponding value, if it exists
userlib.DatastoreDelete(key uuid.UUID)
```

> [!NOTE]
>
> - Keystore is immutable: A name-value pair cannot be modified or deleted after being stored in Keystore.
> - Datastore is mutable: If name already maps to an existing name-value pair, then the existing value will be overwritten with the provided value.

#### UUID

```go
// Returns a randomly generated UUID
uuid.New() (uuid.UUID)

// Creates a new UUID by copying the 16 bytes in b into a new UUID	
//	Returns an error if the byte slice b does not have a length of 16
uuid.FromBytes(b []byte) (uuid uuid.UUID, err error)
```

#### JSON Marshal and Unmarshal

```go
// Converts an arbitrary Go value, v, into a byte slice containing the JSON representation of the struct.
json.Marshal(v interface{}) (bytes []byte, err error)

// Converts a byte slice v, generated by json.Marshal, back into a Go struct.
json.Unmarshal(v []byte, obj interface{}) (err)
```

> [!NOTE]
>
> Only struct fields that start with a capital letter will have their values serialized into json. Struct fields that start with a lowercase letter will be initialized to their default value.

#### Random Byte Generator

```go
// Given a length bytes, return that number of randomly generated bytes
userlib.RandomBytes(bytes int) (data []byte)
```

#### Hash Functions

```go
// Takes in arbitrary-length data, and outputs sum, a 64-byte SHA-512 hash of the data
//	Should use HMACEqual to determine hash equality, because this function runs in constant time and avoids timing side-channel attacks. 
userlib.Hash(data []byte) (sum []byte)

// Deterministically derive a new 64-byte derivedKey
// 	Hashes together a 16-byte sourceKey and some arbitrary-length byte array
// 	HashKDF stands for Hash-Based Key Derivation Function
userlib.HashKDF(sourceKey []byte, purpose []byte) (derivedKey []byte, err error)

// Apply a slow hash to the given password and salt to get an outputted hash
//	Argon2Key is called a Password-Based Key Derivation Function
// 	The hashed password can be used as a symmetric key because attackers cannot brute-force passwords 
userlib.Argon2Key(password []byte, salt []byte, keyLen uint32) (result []byte)
```

#### Symmetric-Key Cryptography

```go
// Encrypts the plaintext using AES-CTR mode with the provided 16-byte key and 16-byte iv
userlib.SymEnc(key []byte, iv []byte, plaintext []byte) (ciphertext []byte)

// Decrypts the ciphertext using the 16-byte key
// 	If ciphertext is less than the length of one cipher block, then the function will panic
//	If ciphertext is mutated the function return non-useful plaintext (no error)
userlib.SymDec(key []byte, ciphertext []byte) (plaintext []byte)

// Takes in an arbitrary-length msg, and a 16-byte key. Computes a 64-byte HMAC-SHA-512 on the message
userlib.HMACEval(key []byte, msg []byte) (sum []byte, err error)

// Compare whether two HMACs (or hashes) a and b are the same, in constant time
userlib.HMACEqual(a []byte, b []byte) (equal bool)
```

#### Public-Key Cryptography

```go
// Generates a 256-byte RSA key pair for public-key encryption
userlib.PKEKeyGen() (PKEEncKey, PKEDecKey, err error)

// Uses the RSA public key ek to encrypt the plaintext, using RSA-OAEP
userlib.PKEEnc(ek PKEEncKey, plaintext []byte) (ciphertext []byte, err error)

// Use the RSA private key dk to decrypt the ciphertext.
userlib.PKEDec(dk PKEDecKey, ciphertext []byte) (plaintext []byte, err error)

// Generates an RSA key pair for digital signatures
userlib.DSKeyGen() (DSSignKey, DSVerifyKey, err error)

// Given an RSA private (signing) key sk and a msg, outputs a 256-byte RSA signature sig
userlib.DSSign(sk DSSignKey, msg []byte) (sig []byte, err error)

// Uses the RSA public (verification) key vk to verify the signature sig on the message msg is valid
userlib.DSVerify(vk DSVerifyKey, msg []byte, sig []byte) (err error)
```

> [!note]
>
> RSA encryption does not support very long plaintext. If you need to use a public key to encrypt long plaintext, consider writing a helper function that implements hybrid encryption.

### Hints

- If you gets some internet error using go, please run  `go env -w GOPROXY=https://goproxy.cn,direct`.
