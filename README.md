# Introduction<a name="EN-US_TOPIC_0000001085515342"></a>

-   **Device interconnection security**

To securely transmit user data between devices, the device authentication module provides the capabilities of establishing and verifying trust relationships between devices. This document describes how an IoT controller and an IoT device establish and verify a trust relationship.

-   **IoT device interconnection security**

The device authentication module allows an IoT controller \(such as a smartphone and tablet\) and an IoT device \(such as a smart home device and wearable\) to establish and verify a P2P trust relationship with each other, without requiring login to the IoT controller and IoT device using the same account. Based on the trust relationship, the IoT controller and IoT device can transmit encrypted user data through a secure P2P connection.

-   **IoT controller identifier**

When a P2P trust relationship is established between the IoT controller and IoT device, a public/private key pair is generated based on the elliptic curve cryptography \(ECC\) and serves as the identifier of the IoT controller. The IoT controller may connect to multiple IoT devices. The device authentication module generates different identifiers for the IoT controller to isolate its connections to different IoT devices.

-   **IoT device identifier**

The IoT device identifier is also a public/private key pair generated based on the ECC when a P2P trust relationship is established between the IoT controller and IoT device. The private key is stored on the IoT device. Each time the device is restored to factory settings, the public/private key pair will be reset.

The preceding identifiers are used for secure communications between the IoT controller and IoT device.

-   **P2P trust relationship establishment and verification**

When an IoT controller and an IoT device establish a P2P trust relationship, they exchange identifiers.

During this process, the user needs to enter the personal identification number \(PIN\) or any other information provided by the IoT device on the IoT controller. Typically, a PIN is dynamically generated if the IoT device has a screen, or preset by the manufacturer if the IoT device does not have a screen. A PIN can be a number consisting of six digits or a QR code. After the user enters the PIN, the IoT controller and IoT device invoke the device authentication service to perform authentication and session key exchange based on the password authenticated key exchange \(PAKE\) protocol, and use the session key to exchange the public keys of their identifiers.

When the IoT controller and IoT device communicate with each other after establishing a trust relationship, they exchange public keys of their identifiers and verify the trust relationship by checking whether they have stored the identity information of each other. Based on their public/private key pairs, the IoT controller and IoT device exchange keys and establish a secure communications channel for transmitting encrypted data.

# Directory Structure<a name="EN-US_TOPIC_0000001085515522"></a>

```
base/security
├── deviceauth
│   ├── frameworks
│   │   └── deviceauth_lite    # Device authentication implementation
│   └── interfaces
│       └── innerkits
│           └── deviceauth_lite # Device authentication APIs
```

# Repositories Involved<a name="EN-US_TOPIC_0000001085355664"></a>

deviceauth
