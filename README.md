# Dridex Automatically String Decryption

This repository contains a Python script for automatically finding and decrypting RC4-encrypted strings in the binary of Dridex malware. Dridex is a notorious banking Trojan that targets financial information through various techniques, including the use of RC4 encryption to obfuscate its strings.

## Features

- Automatically scans the binary for RC4-encrypted strings.
- Defines structures including keys and encrypted strings.
- Decrypts the found RC4 strings.
- Modify the decrypted strings for further analysis.

## Requirements

This code must be used inside Binary Ninja, as most of the core functionalities depend on this tool's APIs.
It is also suggested that it should be run with the `Snippets` plugin from Binary Ninja.

## Examples

![](https://github.com/azhlm/Dridex-Automatically-String-Decryption/blob/main/demo.gif)

## Contributing
Contributions are welcome! Please open an issue or submit a pull request if you have any improvements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
