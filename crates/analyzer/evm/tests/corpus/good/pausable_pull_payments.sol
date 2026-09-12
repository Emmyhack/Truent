// A protocol with a pause switch, bounded paging and pull payments.
pragma solidity ^0.8.20;

contract Rewards is Ownable, Pausable, ReentrancyGuard {
    address[] public holders;
    mapping(address => uint256) public owed;
    mapping(address => uint256) public balances;
    uint256 public cursor;

    function join() external {
        holders.push(msg.sender);
    }

    function deposit() external payable whenNotPaused {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external whenNotPaused nonReentrant {
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function accrue(uint256 page) external onlyOwner {
        uint256 end = cursor + page;
        if (end > holders.length) end = holders.length;
        for (uint256 i = cursor; i < end; i++) {
            owed[holders[i]] += 1 ether;
        }
        cursor = end;
    }

    function claim() external whenNotPaused nonReentrant {
        uint256 amount = owed[msg.sender];
        owed[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function pause() external onlyOwner {
        _pause();
    }
}
