// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Role-based access control in the OpenZeppelin shape. Every privileged
/// function is gated by a role check that reaches the mutation.
contract AccessControl {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    mapping(bytes32 => bytes32) private _roleAdmins;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "AccessControl: account is missing role");
        _;
    }

    constructor(address admin) {
        _roles[DEFAULT_ADMIN_ROLE][admin] = true;
        emit RoleGranted(DEFAULT_ADMIN_ROLE, admin, msg.sender);
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function grantRole(bytes32 role, address account) external onlyRole(_roleAdmins[role]) {
        _roles[role][account] = true;
        emit RoleGranted(role, account, msg.sender);
    }

    function revokeRole(bytes32 role, address account) external onlyRole(_roleAdmins[role]) {
        _roles[role][account] = false;
        emit RoleRevoked(role, account, msg.sender);
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
