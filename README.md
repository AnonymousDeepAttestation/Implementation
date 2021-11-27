# Deep Attestation Implementation

This project corresponds to a proof of concept for a Deep Attestation protocol using multichannel approach with a new linked-attestation mechanism in order to get the good performance of the multichannel approach with improved security.

It is based on full virtualization of the TPM of the virtual machine to attest. We used [swtpm](https://github.com/stefanberger/swtpm) a virtual TPM for QEMU and the [tpm2-tools](https://github.com/tpm2-software) to interact with the TPM. Our implementation uses python to wrap tpm2-tools commands and run TLS client and TLS server. The messages of the protocol are send through the TLS channel as JSON UTF-8 strings. This implementation itself is neither optimized nor secure but demonstrates the feasibility of our protocol.

A documentation in HTML format explaining how to setup a demonstration environment on a simple PC and run the protocol is available in the `doc` folder. For the formal aspects and general principles of the protocol you can refer to the paper.
