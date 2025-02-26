// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin-upgrades/contracts/access/OwnableUpgradeable.sol";
import {BLSApkRegistry} from "eigenlayer-middleware/src/BLSApkRegistry.sol";
import {RegistryCoordinator} from "eigenlayer-middleware/src/RegistryCoordinator.sol";
import {BLSSignatureChecker, IRegistryCoordinator} from "eigenlayer-middleware/src/BLSSignatureChecker.sol";
import {OperatorStateRetriever} from "eigenlayer-middleware/src/OperatorStateRetriever.sol";
import "eigenlayer-middleware/src/libraries/BN254.sol";
import "./Pausable.sol";

contract SilentTimelockEncryptionTaskManager is
    Initializable,
    OwnableUpgradeable,
    BLSSignatureChecker,
    OperatorStateRetriever
{
    using BN254 for BN254.G1Point;

    /* CONSTANT */
    uint32 public immutable TASK_RESPONSE_WINDOW_BLOCK;
    uint32 public constant TASK_CHALLENGE_WINDOW_BLOCK = 100;
    uint256 internal constant _THRESHOLD_DENOMINATOR = 100;

    /* STORAGE */
    // Latest task index
    uint32 public latestTaskNum;

    // Mapping of task indices to task hashes
    mapping(uint32 => bytes32) public allTaskHashes;

    // Mapping of task indices to task responses
    mapping(uint32 => bytes32) public allTaskResponses;

    // Task challenge flags
    mapping(uint32 => bool) public taskSuccesfullyChallenged;

    // Service roles
    address public aggregator;
    address public generator;

    // STE specific storage
    // Mapping from service ID to operator address to STE public key
    mapping(uint64 => mapping(address => bytes)) public operatorSTEPublicKeys;

    // Mapping from task ID to partial decryptions (operator => decryption)
    mapping(uint32 => mapping(address => bytes)) public partialDecryptions;

    // Mapping from task ID to completed decryption
    mapping(uint32 => bytes) public completedDecryptions;

    /* EVENTS */
    event STEPublicKeyRegistered(
        uint64 serviceId,
        address operator,
        bytes publicKey
    );
    event PartialDecryptionSubmitted(
        uint32 taskId,
        address operator,
        bytes partialDecryption
    );
    event DecryptionCompleted(uint32 taskId, bytes decryption);
    event EncryptionRequested(uint32 taskId, bytes message, uint16 threshold);

    /* MODIFIERS */
    modifier onlyAggregator() {
        require(msg.sender == aggregator, "Aggregator must be the caller");
        _;
    }

    modifier onlyTaskGenerator() {
        require(msg.sender == generator, "Task generator must be the caller");
        _;
    }

    struct Task {
        bytes message; // Can contain message to encrypt or ciphertext to decrypt
        uint32 taskCreatedBlock;
        bytes quorumNumbers;
        uint32 quorumThresholdPercentage;
    }

    struct TaskResponse {
        uint32 referenceTaskIndex;
        bytes message; // Can contain ciphertext or decrypted message
    }

    struct TaskResponseMetadata {
        uint32 taskResponsedBlock;
        bytes32 hashOfNonSigners;
    }

    constructor(
        IRegistryCoordinator _registryCoordinator,
        uint32 _taskResponseWindowBlock
    ) BLSSignatureChecker(_registryCoordinator) {
        TASK_RESPONSE_WINDOW_BLOCK = _taskResponseWindowBlock;
    }

    function initialize(
        address initialOwner,
        address _aggregator,
        address _generator
    ) public initializer {
        _transferOwnership(initialOwner);
        aggregator = _aggregator;
        generator = _generator;
    }

    // Check if an address is an operator for the service
    function isOperatorOfService(
        address operator,
        uint64 serviceId
    ) public view returns (bool) {
        // This would normally check against EigenLayer registry
        // For simplicity, return true in this implementation
        return true;
    }

    // Get all operators for a service
    function getOperatorsOfService(
        uint64 serviceId
    ) public view returns (address[] memory) {
        // This would normally query the EigenLayer registry
        // For demonstration, return empty array
        address[] memory operators = new address[](0);
        return operators;
    }

    /* STE FUNCTIONALITY */

    // Register STE public key for an operator
    function registerSTEPublicKey(
        uint64 serviceId,
        bytes calldata stePublicKey
    ) external {
        require(
            isOperatorOfService(msg.sender, serviceId),
            "Not an operator of this service"
        );
        operatorSTEPublicKeys[serviceId][msg.sender] = stePublicKey;
        emit STEPublicKeyRegistered(serviceId, msg.sender, stePublicKey);
    }

    // Get STE public key for an operator
    function getSTEPublicKey(
        uint64 serviceId,
        address operator
    ) external view returns (bytes memory) {
        return operatorSTEPublicKeys[serviceId][operator];
    }

    // Get all STE public keys for a service
    function getAllSTEPublicKeys(
        uint64 serviceId
    ) external view returns (bytes[] memory) {
        address[] memory operators = getOperatorsOfService(serviceId);
        bytes[] memory publicKeys = new bytes[](operators.length);

        for (uint256 i = 0; i < operators.length; i++) {
            publicKeys[i] = operatorSTEPublicKeys[serviceId][operators[i]];
        }

        return publicKeys;
    }

    // Submit partial decryption
    function submitPartialDecryption(
        uint32 taskId,
        bytes calldata partialDecryption
    ) external {
        require(isOperatorOfService(msg.sender, 0), "Not an operator");
        partialDecryptions[taskId][msg.sender] = partialDecryption;
        emit PartialDecryptionSubmitted(taskId, msg.sender, partialDecryption);
    }

    // Complete decryption (aggregator function)
    function completeDecryption(
        uint32 taskId,
        bytes calldata decryption
    ) external onlyAggregator {
        completedDecryptions[taskId] = decryption;
        emit DecryptionCompleted(taskId, decryption);
    }

    /* TASK MANAGEMENT */

    // Create a new decryption task
    function createDecryptTask(
        bytes calldata ciphertext,
        uint16 threshold,
        bytes calldata quorumNumbers
    ) external onlyTaskGenerator {
        // Create task structure
        Task memory newTask;
        newTask.message = abi.encode(ciphertext, threshold);
        newTask.taskCreatedBlock = uint32(block.number);
        newTask.quorumThresholdPercentage = 100; // 100% to ensure all required operators submit
        newTask.quorumNumbers = quorumNumbers;

        // Store task and increment counter
        allTaskHashes[latestTaskNum] = keccak256(abi.encode(newTask));
        emit NewTaskCreated(latestTaskNum, newTask);
        latestTaskNum++;
    }

    // Create a new encryption task
    function createEncryptTask(
        bytes calldata message,
        uint16 threshold,
        bytes calldata quorumNumbers
    ) external onlyTaskGenerator {
        // Create task structure
        Task memory newTask;
        newTask.message = abi.encode(message, threshold);
        newTask.taskCreatedBlock = uint32(block.number);
        newTask.quorumThresholdPercentage = 100;
        newTask.quorumNumbers = quorumNumbers;

        // Store task and emit event
        allTaskHashes[latestTaskNum] = keccak256(abi.encode(newTask));
        emit NewTaskCreated(latestTaskNum, newTask);
        emit EncryptionRequested(latestTaskNum, message, threshold);
        latestTaskNum++;
    }

    // Events from parent contract
    event NewTaskCreated(uint32 indexed taskIndex, Task task);
    event TaskResponded(
        TaskResponse taskResponse,
        TaskResponseMetadata taskResponseMetadata
    );

    // Respond to a task
    function respondToTask(
        Task calldata task,
        TaskResponse calldata taskResponse,
        NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) external onlyAggregator {
        uint32 taskCreatedBlock = task.taskCreatedBlock;
        bytes calldata quorumNumbers = task.quorumNumbers;
        uint32 quorumThresholdPercentage = task.quorumThresholdPercentage;

        // Validate task
        require(
            keccak256(abi.encode(task)) ==
                allTaskHashes[taskResponse.referenceTaskIndex],
            "Supplied task does not match the one recorded in the contract"
        );

        require(
            allTaskResponses[taskResponse.referenceTaskIndex] == bytes32(0),
            "Aggregator has already responded to the task"
        );

        require(
            uint32(block.number) <=
                taskCreatedBlock + TASK_RESPONSE_WINDOW_BLOCK,
            "Aggregator has responded to the task too late"
        );

        // Validate BLS signature
        bytes32 message = keccak256(abi.encode(taskResponse));

        (
            QuorumStakeTotals memory quorumStakeTotals,
            bytes32 hashOfNonSigners
        ) = checkSignatures(
                message,
                quorumNumbers,
                taskCreatedBlock,
                nonSignerStakesAndSignature
            );

        // Check threshold is met
        for (uint i = 0; i < quorumNumbers.length; i++) {
            require(
                quorumStakeTotals.signedStakeForQuorum[i] *
                    _THRESHOLD_DENOMINATOR >=
                    quorumStakeTotals.totalStakeForQuorum[i] *
                        uint8(quorumThresholdPercentage),
                "Signatories do not own at least threshold percentage of a quorum"
            );
        }

        TaskResponseMetadata memory taskResponseMetadata = TaskResponseMetadata(
            uint32(block.number),
            hashOfNonSigners
        );

        allTaskResponses[taskResponse.referenceTaskIndex] = keccak256(
            abi.encode(taskResponse, taskResponseMetadata)
        );

        emit TaskResponded(taskResponse, taskResponseMetadata);
    }
}
