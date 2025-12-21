# Technical Implementation Report: Secure File Sharing System

This report details the architectural design, data structures, and cryptographic protocols used to implement the secure, stateless file sharing system. It includes detailed code-level explanations for critical components.

## 1. System Architecture Overview

![System Architecture Overview](figures/figure1.png)

The system is designed as a **stateless client** interacting with two remote stores:
*   **Keystore (Trusted):** Stores immutable public keys (`PKE`, `DS`).
*   **Datastore (Untrusted):** Stores encrypted and authenticated binary data.

**Key Design Principles:**
*   **Confidentiality & Integrity:** All data written to the Datastore is encrypted using **AES-CTR** and authenticated using **HMAC-SHA512** (Encrypt-then-MAC). This is handled by the helper functions `encryptData` and `verifyAndDecryptData`.
*   **Key Isolation:** Keys are derived uniquely for every purpose using **HashKDF**, preventing key reuse attacks. For example, `user-info-encryption` vs `user-info-hash`.
*   **Efficiency:** File append operations are **O(1)** in bandwidth relative to the total file size.

---

## 2. User Authentication & Session Management

![User Authentication & Session Management](figures/figure2.png)


### Data Structure: `User`
```go
type User struct {
    Username     string
    SourceKey    []byte    // Master key for file list operations
    FileListUUID uuid.UUID // Random pointer to the file list
    PkeEncKey    userlib.PKEEncKey
    PkeDecKey    userlib.PKEDecKey
    DsSigKey     userlib.DSSignKey
    DsVerKey     userlib.DSVerifyKey
}
```
The `User` struct acts as the root of trust. The `FileListUUID` is a critical security feature: it is a random UUID generated at initialization. This "hidden pointer" means that even if an attacker guesses a user's password-derived storage location, they cannot easily enumerate the user's files because the list is stored at a random location known only after decrypting the User struct.

### Login Flow (`InitUser` / `GetUser`)
1.  **Key Derivation (Argon2):**
    ```go
    passwdKey := userlib.Argon2Key([]byte(password), []byte(username), 16)
    ```
    We use Argon2 with the username as salt to generate a high-entropy root key (`passwdKey`). This protects against rainbow table attacks.

2.  **Deterministic Storage Location:**
    ```go
    uuidBytes, _ := userlib.HashKDF(passwdKey, []byte("user-uuid"))
    userUUID, _ := uuid.FromBytes(uuidBytes[:16])
    ```
    The storage UUID for the User struct is deterministically derived from the password key. This allows the user to "bootstrap" their session from any device without a central directory.

3.  **Authenticated Encryption:**
    The User struct is serialized to JSON and then encrypted.
    ```go
    encRes, err := encryptData(encKey, hashKey, userBytes)
    userlib.DatastoreSet(userUUID, encRes)
    ```
    `encryptData` internally generates a random IV for AES-CTR and computes an HMAC-SHA512 tag over the ciphertext. `verifyAndDecryptData` in `GetUser` ensures that if the Datastore adversary modifies the User blob, the client will detect it and reject the login.

---

## 3. File System Design

![File System Design](figures/figure3.png)


### Efficient Storage Structure
Files are stored as a **Linked List of Blocks** to support efficient appending.

**1. FileMetadata (The Inode):**
```go
type FileMetadata struct {
    Owner         string
    HeadNodeUUID  uuid.UUID // Pointer to start of file
    TailNodeUUID  uuid.UUID // Pointer to end of file (for fast append)
    ContentKey    []byte    // Symmetric key for file content
}
```
The `TailNodeUUID` is the secret sauce for O(1) appends. It allows us to jump directly to the end of the file without traversing the list.

**2. FileNode (The Block):**
```go
type FileNode struct {
    Content []byte
    Next    uuid.UUID // Pointer to next block
}
```

### Operations

*   **StoreFile:**
    Creates a new `FileMetadata` and the first `FileNode`. It generates a random `ContentKey`. The metadata itself is encrypted using a key (`MetaEncKey`) stored in the user's private `FileEntry`.

*   **LoadFile:**
    Fetches the Metadata, then iteratively fetches `FileNode`s starting from `HeadNodeUUID` until `Next == uuid.Nil`. Each node is decrypted using keys derived from `ContentKey` and the node's unique UUID (to prevent block swapping attacks).

*   **AppendToFile (Efficiency O(1)):**
    ```go
    // 1. Fetch Metadata (Constant size)
    metadata, _ := getMetadata(...)

    // 2. Create New Node
    newNodeUUID := uuid.New()
    // ... encrypt and store newNode ...

    // 3. Update Old Tail
    tailNode := fetchAndDecrypt(metadata.TailNodeUUID, ...)
    tailNode.Next = newNodeUUID
    // ... encrypt and store tailNode ...

    // 4. Update Metadata
    metadata.TailNodeUUID = newNodeUUID
    // ... encrypt and store metadata ...
    ```
    This logic ensures bandwidth usage is proportional only to the size of the appended data + constant metadata overhead, satisfying the efficiency requirement.

---

## 4. Sharing Mechanism ("The Lockbox")

Sharing uses an **indirect access** model via a `ShareNode`. This level of indirection is crucial for revocation.

### Data Structures
```go
// The "Lockbox"
type ShareNode struct {
    MetaEncKey   []byte    // Key to decrypt the file metadata
    MetadataUUID uuid.UUID // Location of the file metadata
}

// The Invitation
type Invitation struct {
    ShareNodeUUID uuid.UUID // Location of the lockbox
    ShareNodeKey  []byte    // Key to open the lockbox
}
```

### Protocol Flow
1.  **CreateInvitation:**
    *   The owner creates a `ShareNode` containing the file's current `MetaEncKey`.
    *   This `ShareNode` is encrypted with a random `ShareNodeKey`.
    *   **Security:** The invitation is signed (`DSSign`) by the sender to prevent spoofing and encrypted (`PKEEnc` + `SymEnc` hybrid) for the recipient to ensure confidentiality.
    *   **Revocation Tracking:** The owner stores the `ShareNodeUUID` in their `RevocationMap` so they can locate it later if they need to update keys.

2.  **AcceptInvitation:**
    *   The recipient decrypts the invitation and verifies the signature.
    *   They store the `ShareNode` location in their own `FileEntry`.
    *   To access the file: `Recipient` -> `ShareNode` -> `FileMetadata` -> `FileNodes`.

---

## 5. Revocation Strategy (Key Rotation)

![Revocation Strategy](figures/figure4.png)


Revocation is implemented using **Lazy Revocation** via key rotation.

**The Algorithm (`RevokeAccess`):**

```go
func (userdata *User) RevokeAccess(...) {
    // 1. Generate NEW keys
    newMetaEncKey := userlib.RandomBytes(16)

    // 2. Re-encrypt Metadata with the NEW key
    metadata := fetchAndDecrypt(oldKey, ...)
    encryptAndStore(metadata, newKey, ...)

    // 3. Update Valid Users
    for user, info := range entry.RevocationMap {
        if user != revokedUser {
            // Update their ShareNode to contain the NEW key
            newShareNode := ShareNode{ MetaEncKey: newMetaEncKey, ... }
            encryptAndStore(newShareNode, ..., info.ShareNodeUUID)
        }
    }
    // The revoked user's ShareNode is NOT updated.
}
```

**Why this works:**
*   The `FileMetadata` is now encrypted with `newMetaEncKey`.
*   Valid users have their `ShareNode`s updated to contain `newMetaEncKey`, so they can still decrypt the metadata.
*   The revoked user still has their old `ShareNode`, which contains `oldMetaEncKey`.
*   When the revoked user tries to `LoadFile`, they get `oldMetaEncKey`, fetch the metadata, and try to decrypt/verify it. **This fails** because the metadata is now encrypted with a different key (and the MAC check will fail).
*   The revoked user is effectively locked out of the file's current state and any future updates.

---

## 6. Security Analysis Summary

| **Attack Vector** | **Mitigation Strategy** |
| :--- | :--- |
| **Datastore Tampering** | HMAC-SHA512 (Encrypt-then-MAC) on every object. |
| **Key Reuse** | HashKDF with unique purpose strings for key isolation. |
| **Swap/Replay Attack** | Inclusion of the object's own UUID in the HMAC calculation. |
| **Unauthorized Access** | Hybrid PKE (RSA-OAEP) and Signed Invitations for sharing. |
| **Post-Revocation Access** | Meta-key rotation and Indirection node (ShareNode) updates. |