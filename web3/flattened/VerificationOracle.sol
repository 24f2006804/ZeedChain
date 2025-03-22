PrivateKey set: true
// Sources flattened with hardhat v2.22.19 https://hardhat.org

// SPDX-License-Identifier: MIT

// File @openzeppelin/contracts/utils/Context.sol@v4.9.3

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)

pragma solidity ^0.8.0;

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}


// File @openzeppelin/contracts/access/Ownable.sol@v4.9.3

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (access/Ownable.sol)

pragma solidity ^0.8.0;

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor() {
        _transferOwnership(_msgSender());
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}


// File contracts/chainlink-functions/dev/interfaces/FunctionsResponseTypes.sol

// Original license: SPDX_License_Identifier: MIT
pragma solidity ^0.8.20;

library FunctionsResponse {
    enum Status {
        NONE,
        PENDING,
        FULFILLED,
        ERROR
    }

    struct Commitment {
        bytes data;
        bytes error;
        Status status;
    }

    function encode(string memory data) internal pure returns (bytes memory) {
        return abi.encode(data);
    }

    function encodeUint(uint256 data) internal pure returns (bytes memory) {
        return abi.encode(data);
    }

    function encodeBool(bool data) internal pure returns (bytes memory) {
        return abi.encode(data);
    }

    function encodeBytes(bytes memory data) internal pure returns (bytes memory) {
        return data;
    }
}


// File contracts/chainlink-functions/dev/v1_0_0/interfaces/IFunctionsClient.sol

// Original license: SPDX_License_Identifier: MIT
pragma solidity ^0.8.20;

interface IFunctionsClient {
    function handleOracleFulfillment(
        bytes32 requestId,
        bytes memory response,
        bytes memory err
    ) external;
}


// File contracts/chainlink-functions/dev/v1_0_0/FunctionsRouter.sol

// Original license: SPDX_License_Identifier: MIT
pragma solidity ^0.8.20;


contract FunctionsRouter {
    using FunctionsResponse for FunctionsResponse.Commitment;

    mapping(bytes32 => FunctionsResponse.Commitment) private s_commitments;
    mapping(bytes32 => address) private s_requesters;

    event RequestProcessed(bytes32 indexed id, bytes response, bytes err);
    event RequestSent(bytes32 indexed id, address indexed requester);

    function sendRequest(
        uint64 subscriptionId,
        bytes calldata data,
        uint32 gasLimit,
        bytes32 donId
    ) external returns (bytes32) {
        bytes32 requestId = keccak256(abi.encodePacked(block.timestamp, msg.sender, subscriptionId));
        s_requesters[requestId] = msg.sender;
        s_commitments[requestId] = FunctionsResponse.Commitment({
            data: data,
            error: new bytes(0),
            status: FunctionsResponse.Status.PENDING
        });

        emit RequestSent(requestId, msg.sender);
        return requestId;
    }

    function fulfill(
        bytes32 requestId,
        bytes memory response,
        bytes memory err
    ) external {
        address requester = s_requesters[requestId];
        require(requester != address(0), "Request not found");

        FunctionsResponse.Commitment storage commitment = s_commitments[requestId];
        require(commitment.status == FunctionsResponse.Status.PENDING, "Request already fulfilled");

        if (err.length > 0) {
            commitment.status = FunctionsResponse.Status.ERROR;
            commitment.error = err;
        } else {
            commitment.status = FunctionsResponse.Status.FULFILLED;
            commitment.data = response;
        }

        IFunctionsClient(requester).handleOracleFulfillment(requestId, response, err);
        emit RequestProcessed(requestId, response, err);
    }

    function getRequestConfig() external pure returns (
        uint32 fulfillmentGasLimit,
        uint32 requestTimeoutSeconds
    ) {
        return (300000, 300);
    }

    function getCommitment(bytes32 requestId) external view returns (
        bytes memory data,
        bytes memory error,
        FunctionsResponse.Status status
    ) {
        FunctionsResponse.Commitment memory commitment = s_commitments[requestId];
        return (commitment.data, commitment.error, commitment.status);
    }
}


// File contracts/chainlink-functions/dev/v1_0_0/FunctionsClient.sol

// Original license: SPDX_License_Identifier: MIT
pragma solidity ^0.8.20;



abstract contract FunctionsClient is IFunctionsClient {
    FunctionsRouter internal immutable i_router;

    constructor(address router) {
        i_router = FunctionsRouter(router);
    }

    function handleOracleFulfillment(
        bytes32 requestId,
        bytes memory response,
        bytes memory err
    ) external override {
        require(msg.sender == address(i_router), "Only router can fulfill");
        fulfillRequest(requestId, response, err);
    }

    function _sendRequest(
        bytes memory data,
        uint64 subscriptionId,
        uint32 gasLimit,
        bytes32 donId
    ) internal returns (bytes32) {
        return i_router.sendRequest(
            subscriptionId,
            data,
            gasLimit,
            donId
        );
    }

    function fulfillRequest(
        bytes32 requestId,
        bytes memory response,
        bytes memory err
    ) internal virtual;
}


// File @openzeppelin/contracts/security/ReentrancyGuard.sol@v4.9.3

// Original license: SPDX_License_Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (security/ReentrancyGuard.sol)

pragma solidity ^0.8.0;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be _NOT_ENTERED
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == _ENTERED;
    }
}


// File contracts/chainlink-functions/dev/v1_0_0/FunctionsRequest.sol

// Original license: SPDX_License_Identifier: MIT
pragma solidity ^0.8.20;

library FunctionsRequest {
    struct Request {
        string source;
        bytes encryptedSecretsReference;
        string[] args;
        bytes[] bytesArgs;
    }

    function initializeRequest(
        Request memory self,
        string memory source
    ) internal pure {
        self.source = source;
    }

    function initializeRequestForInlineJavaScript(
        Request memory self,
        string memory source
    ) internal pure {
        self.source = source;
    }

    function addArgs(Request memory self, string[] memory args) internal pure {
        require(self.args.length == 0, "Args already set");
        self.args = args;
    }

    function addBytesArgs(Request memory self, bytes[] memory args) internal pure {
        require(self.bytesArgs.length == 0, "Bytes args already set");
        self.bytesArgs = args;
    }

    function setArgs(Request memory self, string[] memory args) internal pure {
        self.args = args;
    }

    function encodeCBOR(Request memory self) internal pure returns (bytes memory) {
        return abi.encode(self.source, self.args, self.bytesArgs);
    }
}


// File contracts/VerificationOracle.sol

// Original license: SPDX_License_Identifier: MIT
pragma solidity ^0.8.20;





contract VerificationOracle is FunctionsClient, Ownable, ReentrancyGuard {
    using FunctionsRequest for FunctionsRequest.Request;

    struct VerificationData {
        bool kycPassed;
        bool amlPassed;
        string credentialHash;
        string verificationSource;
        uint256 timestamp;
        bool isValid;
        bytes32 lastRequestId;
    }
    
    mapping(address => VerificationData) public userVerifications;
    mapping(bytes32 => address) private requestToUser;
    mapping(bytes32 => uint8) private requestTypes; // Track request types
    
    // Request type constants
    uint8 private constant KYC_REQUEST = 64;
    uint8 private constant AML_REQUEST = 160;
    uint8 private constant CREDENTIALS_REQUEST = 224;
    
    event VerificationRequested(bytes32 indexed requestId, address indexed user);
    event VerificationCompleted(
        address indexed user,
        bool kycPassed,
        bool amlPassed,
        string credentialHash,
        string verificationSource
    );
    event RequestFailed(bytes32 indexed requestId, bytes reason);
    
    uint64 private s_subscriptionId;
    bytes32 private s_donId;
    uint32 private s_gasLimit;
    bytes private s_kycSource;
    bytes private s_amlSource;
    bytes private s_credentialsSource;

    constructor(
        address router,
        uint64 subscriptionId,
        bytes32 donId,
        bytes memory kycSource,
        bytes memory amlSource,
        bytes memory credentialsSource
    ) FunctionsClient(router) {
        if (router == address(0)) revert("Invalid router address");
        
        s_subscriptionId = subscriptionId;
        s_donId = donId;
        s_gasLimit = 300000;
        s_kycSource = kycSource;
        s_amlSource = amlSource;
        s_credentialsSource = credentialsSource;
    }
    
    function requestVerification(
        address user,
        string calldata documentHash
    ) external returns (bytes32) {
        // Clean up old request if it exists
        bytes32 oldRequestId = userVerifications[user].lastRequestId;
        if (oldRequestId != bytes32(0)) {
            delete requestToUser[oldRequestId];
            delete requestTypes[oldRequestId];
        }

        string[] memory args = new string[](2);
        args[0] = addressToString(user);
        args[1] = documentHash;

        FunctionsRequest.Request memory req;
        req.initializeRequestForInlineJavaScript(string(s_kycSource));
        req.setArgs(args);

        bytes32 requestId = _sendRequest(
            req.encodeCBOR(),
            s_subscriptionId,
            s_gasLimit,
            s_donId
        );

        requestToUser[requestId] = user;
        requestTypes[requestId] = KYC_REQUEST;
        userVerifications[user].lastRequestId = requestId;
        emit VerificationRequested(requestId, user);
        
        return requestId;
    }
    
    function fulfillRequest(
        bytes32 requestId,
        bytes memory response,
        bytes memory err
    ) internal override {
        address user = requestToUser[requestId];
        require(user != address(0), "Unknown request");

        // Get the request type
        uint8 requestType = requestTypes[requestId];

        // Clean up request mappings
        delete requestToUser[requestId];
        delete requestTypes[requestId];

        if (err.length > 0) {
            emit RequestFailed(requestId, err);
            if (requestType == KYC_REQUEST) {
                finalizeVerification(user, false, false, "", "KYC Failed");
            } else if (requestType == AML_REQUEST) {
                finalizeVerification(user, userVerifications[user].kycPassed, false, "", "AML Check Failed");
            } else {
                finalizeVerification(user, userVerifications[user].kycPassed, userVerifications[user].amlPassed, "", "Credentials Failed");
            }
            return;
        }
        
        // Check if this is a KYC response
        if (requestType == KYC_REQUEST) {
            bool kycPassed;
            // Try to decode the response, if it fails assume false
            try this.decodeResponse(response) returns (bool result) {
                kycPassed = result;
            } catch {
                kycPassed = false;
            }
            
            if (kycPassed) {
                userVerifications[user].kycPassed = true;
                requestAMLCheck(user);
            } else {
                finalizeVerification(user, false, false, "", "KYC Failed");
            }
        }
        // Check if this is an AML response
        else if (requestType == AML_REQUEST) {
            bool amlPassed;
            // Try to decode the response, if it fails assume false
            try this.decodeResponse(response) returns (bool result) {
                amlPassed = result;
            } catch {
                amlPassed = false;
            }
            
            userVerifications[user].amlPassed = amlPassed;
            
            if (amlPassed && userVerifications[user].kycPassed) {
                requestCredentialsValidation(user);
            } else {
                finalizeVerification(user, userVerifications[user].kycPassed, amlPassed, "", "AML Check Failed");
            }
        }
        // Must be a credentials response
        else {
            try this.decodeCredentialsResponse(response) returns (string memory hash, string memory source) {
                finalizeVerification(
                    user,
                    userVerifications[user].kycPassed,
                    userVerifications[user].amlPassed,
                    hash,
                    source
                );
            } catch {
                finalizeVerification(
                    user,
                    userVerifications[user].kycPassed,
                    userVerifications[user].amlPassed,
                    "",
                    "Credentials Failed"
                );
            }
        }
    }

    // Helper functions for decoding responses externally to allow try/catch
    function decodeResponse(bytes memory response) external pure returns (bool) {
        return abi.decode(response, (bool));
    }

    function decodeCredentialsResponse(bytes memory response) external pure returns (string memory, string memory) {
        return abi.decode(response, (string, string));
    }

    function requestAMLCheck(address user) internal {
        // Clean up old request if it exists
        bytes32 oldRequestId = userVerifications[user].lastRequestId;
        if (oldRequestId != bytes32(0)) {
            delete requestToUser[oldRequestId];
            delete requestTypes[oldRequestId];
        }

        string[] memory args = new string[](1);
        args[0] = addressToString(user);

        FunctionsRequest.Request memory req;
        req.initializeRequestForInlineJavaScript(string(s_amlSource));
        req.setArgs(args);

        bytes32 requestId = _sendRequest(
            req.encodeCBOR(),
            s_subscriptionId,
            s_gasLimit,
            s_donId
        );

        requestToUser[requestId] = user;
        requestTypes[requestId] = AML_REQUEST;
        userVerifications[user].lastRequestId = requestId;
        emit VerificationRequested(requestId, user);
    }

    function requestCredentialsValidation(address user) internal {
        // Clean up old request if it exists
        bytes32 oldRequestId = userVerifications[user].lastRequestId;
        if (oldRequestId != bytes32(0)) {
            delete requestToUser[oldRequestId];
            delete requestTypes[oldRequestId];
        }

        string[] memory args = new string[](1);
        args[0] = addressToString(user);

        FunctionsRequest.Request memory req;
        req.initializeRequestForInlineJavaScript(string(s_credentialsSource));
        req.setArgs(args);

        bytes32 requestId = _sendRequest(
            req.encodeCBOR(),
            s_subscriptionId,
            s_gasLimit,
            s_donId
        );

        requestToUser[requestId] = user;
        requestTypes[requestId] = CREDENTIALS_REQUEST;
        userVerifications[user].lastRequestId = requestId;
        emit VerificationRequested(requestId, user);
    }
    
    function finalizeVerification(
        address user,
        bool kycPassed,
        bool amlPassed,
        string memory credentialHash,
        string memory source
    ) internal {
        VerificationData storage data = userVerifications[user];
        data.kycPassed = kycPassed;
        data.amlPassed = amlPassed;
        data.credentialHash = credentialHash;
        data.verificationSource = source;
        data.timestamp = block.timestamp;
        data.isValid = true;
        
        emit VerificationCompleted(
            user,
            kycPassed,
            amlPassed,
            credentialHash,
            source
        );
    }
    
    function getVerificationStatus(address user) external view returns (
        bool kycPassed,
        bool amlPassed,
        string memory credentialHash,
        string memory verificationSource,
        uint256 timestamp,
        bool isValid
    ) {
        VerificationData memory data = userVerifications[user];
        return (
            data.kycPassed,
            data.amlPassed,
            data.credentialHash,
            data.verificationSource,
            data.timestamp,
            data.isValid
        );
    }
    
    function updateConfig(
        uint64 subscriptionId,
        bytes32 donId,
        uint32 gasLimit,
        bytes calldata kycSource,
        bytes calldata amlSource,
        bytes calldata credentialsSource
    ) external onlyOwner {
        s_subscriptionId = subscriptionId;
        s_donId = donId;
        s_gasLimit = gasLimit;
        s_kycSource = kycSource;
        s_amlSource = amlSource;
        s_credentialsSource = credentialsSource;
    }

    function addressToString(address _address) internal pure returns(string memory) {
        bytes32 value = bytes32(uint256(uint160(_address)));
        bytes memory alphabet = "0123456789abcdef";

        bytes memory str = new bytes(42);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < 20; i++) {
            str[2+i*2] = alphabet[uint8(value[i + 12] >> 4)];
            str[3+i*2] = alphabet[uint8(value[i + 12] & 0x0f)];
        }
        return string(str);
    }
}
