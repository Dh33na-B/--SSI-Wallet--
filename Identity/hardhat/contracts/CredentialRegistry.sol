// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CredentialRegistry {
    struct CredentialRecord {
        bytes32 vcHash;
        bool exists;
        bool revoked;
        uint256 anchoredAt;
        uint256 revokedAt;
    }

    address public owner;
    mapping(string => CredentialRecord) private credentials;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event CredentialAnchored(
        string indexed credentialId,
        bytes32 indexed vcHash,
        address indexed anchoredBy,
        uint256 anchoredAt
    );
    event CredentialRevoked(
        string indexed credentialId,
        bytes32 indexed vcHash,
        address indexed revokedBy,
        uint256 revokedAt
    );

    error Unauthorized();
    error InvalidCredentialId();
    error InvalidVcHash();
    error CredentialAlreadyAnchored();
    error CredentialNotFound();
    error CredentialAlreadyRevoked();
    error InvalidOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert InvalidOwner();
        address previousOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    function anchorCredential(string calldata credentialId, bytes32 vcHash) external onlyOwner returns (bool) {
        if (bytes(credentialId).length == 0) revert InvalidCredentialId();
        if (vcHash == bytes32(0)) revert InvalidVcHash();

        CredentialRecord storage record = credentials[credentialId];
        if (record.exists) revert CredentialAlreadyAnchored();

        record.vcHash = vcHash;
        record.exists = true;
        record.revoked = false;
        record.anchoredAt = block.timestamp;
        record.revokedAt = 0;

        emit CredentialAnchored(credentialId, vcHash, msg.sender, block.timestamp);
        return true;
    }

    function revokeCredential(string calldata credentialId) external onlyOwner returns (bool) {
        if (bytes(credentialId).length == 0) revert InvalidCredentialId();

        CredentialRecord storage record = credentials[credentialId];
        if (!record.exists) revert CredentialNotFound();
        if (record.revoked) revert CredentialAlreadyRevoked();

        record.revoked = true;
        record.revokedAt = block.timestamp;

        emit CredentialRevoked(credentialId, record.vcHash, msg.sender, block.timestamp);
        return true;
    }

    function isCredentialAnchored(string calldata credentialId) external view returns (bool) {
        return credentials[credentialId].exists;
    }

    function isCredentialRevoked(string calldata credentialId) external view returns (bool) {
        CredentialRecord storage record = credentials[credentialId];
        return record.exists && record.revoked;
    }

    function getCredential(
        string calldata credentialId
    ) external view returns (bytes32 vcHash, bool anchored, bool revoked, uint256 anchoredAt, uint256 revokedAt) {
        CredentialRecord storage record = credentials[credentialId];
        return (record.vcHash, record.exists, record.revoked, record.anchoredAt, record.revokedAt);
    }
}
