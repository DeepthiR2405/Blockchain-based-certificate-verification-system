import solcx
from solcx import compile_standard
import json

# Ensure Solidity compiler is installed
solcx.install_solc("0.8.0")

# Read the Solidity contract
with open("CertificateRegistry.sol", "r") as file:
    contract_source_code = file.read()

# Compile the contract
compiled_sol = compile_standard(
    {
        "language": "Solidity",
        "sources": {"CertificateRegistry.sol": {"content": contract_source_code}},
        "settings": {"outputSelection": {"*": {"*": ["abi", "evm.bytecode"]}}},
    },
    solc_version="0.8.0",
)

# Save compiled contract
with open("compiled_contract.json", "w") as file:
    json.dump(compiled_sol, file)

print("Smart contract compiled successfully!")
