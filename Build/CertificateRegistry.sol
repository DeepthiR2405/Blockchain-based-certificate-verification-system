// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CertificateRegistry {
    struct Certificate {
        string studentName;
        string course;
        string certHash;
        bool isValid;
    }

    mapping(string => Certificate) public certificates; // Mapping certHash to Certificate

    event CertificateIssued(string certHash, string studentName, string course);
    event CertificateVerified(string certHash, bool isValid);

    function issueCertificate(string memory _studentName, string memory _course, string memory _certHash) public {
        require(!certificates[_certHash].isValid, "Certificate already exists");

        certificates[_certHash] = Certificate({
            studentName: _studentName,
            course: _course,
            certHash: _certHash,
            isValid: true
        });

        emit CertificateIssued(_certHash, _studentName, _course);
    }

    function verifyCertificate(string memory _certHash) public view returns (string memory studentName, string memory course, bool isValid) {
        require(certificates[_certHash].isValid, "Certificate not found");
        
        Certificate memory cert = certificates[_certHash];

        // **REMOVED THE EMIT STATEMENT** (since view functions cannot modify state)
        return (cert.studentName, cert.course, cert.isValid);
    }
}
