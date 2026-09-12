// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// A 2-of-3 multisig behind a 48-hour timelock. Threshold is a constructor
/// argument validated to be a real majority; executions are delayed.
contract TimelockMultisig {
    address[] public signers;
    uint256 public immutable threshold;
    uint256 public constant DELAY = 48 hours;

    struct Proposal {
        address target;
        bytes data;
        uint256 readyAt;
        uint256 approvals;
        bool executed;
        mapping(address => bool) approved;
    }

    mapping(uint256 => Proposal) private _proposals;
    uint256 public proposalCount;

    event Proposed(uint256 indexed id, address target);
    event Approved(uint256 indexed id, address signer);
    event Executed(uint256 indexed id);

    modifier onlySigner() {
        bool ok;
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == msg.sender) { ok = true; break; }
        }
        require(ok, "not a signer");
        _;
    }

    constructor(address[] memory signers_, uint256 threshold_) {
        require(signers_.length >= 3, "need 3 signers");
        require(threshold_ * 2 > signers_.length, "threshold must be a majority");
        signers = signers_;
        threshold = threshold_;
    }

    function propose(address target, bytes calldata data) external onlySigner returns (uint256 id) {
        id = ++proposalCount;
        Proposal storage p = _proposals[id];
        p.target = target;
        p.data = data;
        p.readyAt = block.timestamp + DELAY;
        emit Proposed(id, target);
    }

    function approve(uint256 id) external onlySigner {
        Proposal storage p = _proposals[id];
        require(!p.approved[msg.sender], "already approved");
        p.approved[msg.sender] = true;
        p.approvals += 1;
        emit Approved(id, msg.sender);
    }

    function execute(uint256 id) external onlySigner {
        Proposal storage p = _proposals[id];
        require(!p.executed, "executed");
        require(p.approvals >= threshold, "insufficient approvals");
        require(block.timestamp >= p.readyAt, "timelocked");
        p.executed = true;
        (bool ok, ) = p.target.call(p.data);
        require(ok, "call failed");
        emit Executed(id);
    }
}
