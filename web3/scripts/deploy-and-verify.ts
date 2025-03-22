import { ethers, run } from "hardhat";
import { EDUCHAIN } from "../utils/config";
import * as fs from 'fs';

async function verifyContract(address: string, args: any[], contractPath: string) {
  console.log(`Verifying ${contractPath} at ${address}...`);
  try {
    await run("verify:verify", {
      address: address,
      constructorArguments: args,
      contract: contractPath
    });
    console.log("Verification successful");
  } catch (error: any) {
    if (error.message.includes("Already Verified")) {
      console.log("Contract already verified");
    } else {
      console.error("Verification failed:", error);
    }
  }
}

async function delay(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying and verifying contracts with account:", deployer.address);

  // Deploy EquityNFTFactory
  const EquityNFTFactory = await ethers.getContractFactory("EquityNFTFactory");
  const equityNFTFactory = await EquityNFTFactory.deploy();
  await equityNFTFactory.waitForDeployment();
  console.log("EquityNFTFactory deployed to:", await equityNFTFactory.getAddress());

  // Deploy FractionalInvestment
  const FractionalInvestment = await ethers.getContractFactory("FractionalInvestment");
  const fractionalInvestment = await FractionalInvestment.deploy(
    await equityNFTFactory.getAddress(),
    deployer.address
  );
  await fractionalInvestment.waitForDeployment();
  console.log("FractionalInvestment deployed to:", await fractionalInvestment.getAddress());

  // Deploy other contracts...
  const DynamicValuation = await ethers.getContractFactory("DynamicValuation");
  const dynamicValuation = await DynamicValuation.deploy(await equityNFTFactory.getAddress());
  await dynamicValuation.waitForDeployment();
  console.log("DynamicValuation deployed to:", await dynamicValuation.getAddress());

  const StartupValidation = await ethers.getContractFactory("StartupValidation");
  const startupValidation = await StartupValidation.deploy(await equityNFTFactory.getAddress(), 3);
  await startupValidation.waitForDeployment();
  console.log("StartupValidation deployed to:", await startupValidation.getAddress());

  const StakeholderGovernance = await ethers.getContractFactory("StakeholderGovernance");
  const stakeholderGovernance = await StakeholderGovernance.deploy(await fractionalInvestment.getAddress());
  await stakeholderGovernance.waitForDeployment();
  console.log("StakeholderGovernance deployed to:", await stakeholderGovernance.getAddress());

  const ProfitDistribution = await ethers.getContractFactory("ProfitDistribution");
  const profitDistribution = await ProfitDistribution.deploy(await fractionalInvestment.getAddress());
  await profitDistribution.waitForDeployment();
  console.log("ProfitDistribution deployed to:", await profitDistribution.getAddress());

  // Oracle contracts
  const AIAdvisorIntegration = await ethers.getContractFactory("AIAdvisorIntegration");
  const aiAdvisor = await AIAdvisorIntegration.deploy(
    EDUCHAIN.CHAINLINK_ORACLE,
    352n,
    EDUCHAIN.FUNCTIONS_DON_ID,
    ethers.toUtf8Bytes("ai_source")
  );
  await aiAdvisor.waitForDeployment();
  console.log("AIAdvisorIntegration deployed to:", await aiAdvisor.getAddress());

  const FinancialDataOracle = await ethers.getContractFactory("FinancialDataOracle");
  const financialDataOracle = await FinancialDataOracle.deploy(
    EDUCHAIN.CHAINLINK_ORACLE,
    352n,
    EDUCHAIN.FUNCTIONS_DON_ID,
    ethers.toUtf8Bytes("financial_source")
  );
  await financialDataOracle.waitForDeployment();
  console.log("FinancialDataOracle deployed to:", await financialDataOracle.getAddress());

  const VerificationOracle = await ethers.getContractFactory("VerificationOracle");
  const verificationOracle = await VerificationOracle.deploy(
    EDUCHAIN.CHAINLINK_ORACLE,
    352n,
    EDUCHAIN.FUNCTIONS_DON_ID,
    ethers.toUtf8Bytes("kyc-verification-job"),
    ethers.toUtf8Bytes("aml-check-job"),
    ethers.toUtf8Bytes("credentials-validation-job")
  );
  await verificationOracle.waitForDeployment();
  console.log("VerificationOracle deployed to:", await verificationOracle.getAddress());

  const PerformanceMetricsOracle = await ethers.getContractFactory("PerformanceMetricsOracle");
  const performanceMetricsOracle = await PerformanceMetricsOracle.deploy(
    EDUCHAIN.CHAINLINK_ORACLE,
    352n,
    EDUCHAIN.FUNCTIONS_DON_ID,
    ethers.toUtf8Bytes("performance_source")
  );
  await performanceMetricsOracle.waitForDeployment();
  console.log("PerformanceMetricsOracle deployed to:", await performanceMetricsOracle.getAddress());

  // Save deployment addresses
  const deployedContracts = {
    equityNFTFactory: await equityNFTFactory.getAddress(),
    fractionalInvestment: await fractionalInvestment.getAddress(),
    dynamicValuation: await dynamicValuation.getAddress(),
    startupValidation: await startupValidation.getAddress(),
    stakeholderGovernance: await stakeholderGovernance.getAddress(),
    profitDistribution: await profitDistribution.getAddress(),
    aiAdvisor: await aiAdvisor.getAddress(),
    financialDataOracle: await financialDataOracle.getAddress(),
    verificationOracle: await verificationOracle.getAddress(),
    performanceMetricsOracle: await performanceMetricsOracle.getAddress()
  };

  fs.writeFileSync(
    "deployed-contracts.json",
    JSON.stringify(deployedContracts, null, 2)
  );

  // Wait a bit before verification to ensure contracts are properly propagated
  console.log("Waiting 30 seconds before verification...");
  await delay(30000);

  // Verify all contracts
  await verifyContract(
    await equityNFTFactory.getAddress(),
    [],
    "contracts/EquityNFTFactory.sol:EquityNFTFactory"
  );

  await verifyContract(
    await fractionalInvestment.getAddress(),
    [await equityNFTFactory.getAddress(), deployer.address],
    "contracts/FractionalInvestment.sol:FractionalInvestment"
  );

  await verifyContract(
    await dynamicValuation.getAddress(),
    [await equityNFTFactory.getAddress()],
    "contracts/DynamicValuation.sol:DynamicValuation"
  );

  await verifyContract(
    await startupValidation.getAddress(),
    [await equityNFTFactory.getAddress(), 3],
    "contracts/StartupValidation.sol:StartupValidation"
  );

  await verifyContract(
    await stakeholderGovernance.getAddress(),
    [await fractionalInvestment.getAddress()],
    "contracts/StakeholderGovernance.sol:StakeholderGovernance"
  );

  await verifyContract(
    await profitDistribution.getAddress(),
    [await fractionalInvestment.getAddress()],
    "contracts/ProfitDistribution.sol:ProfitDistribution"
  );

  await verifyContract(
    await aiAdvisor.getAddress(),
    [EDUCHAIN.CHAINLINK_ORACLE, 352n, EDUCHAIN.FUNCTIONS_DON_ID, ethers.toUtf8Bytes("ai_source")],
    "contracts/AIAdvisorIntegration.sol:AIAdvisorIntegration"
  );

  await verifyContract(
    await financialDataOracle.getAddress(),
    [EDUCHAIN.CHAINLINK_ORACLE, 352n, EDUCHAIN.FUNCTIONS_DON_ID, ethers.toUtf8Bytes("financial_source")],
    "contracts/FinancialDataOracle.sol:FinancialDataOracle"
  );

  await verifyContract(
    await verificationOracle.getAddress(),
    [
      EDUCHAIN.CHAINLINK_ORACLE,
      352n,
      EDUCHAIN.FUNCTIONS_DON_ID,
      ethers.toUtf8Bytes("kyc-verification-job"),
      ethers.toUtf8Bytes("aml-check-job"),
      ethers.toUtf8Bytes("credentials-validation-job")
    ],
    "contracts/VerificationOracle.sol:VerificationOracle"
  );

  await verifyContract(
    await performanceMetricsOracle.getAddress(),
    [EDUCHAIN.CHAINLINK_ORACLE, 352n, EDUCHAIN.FUNCTIONS_DON_ID, ethers.toUtf8Bytes("performance_source")],
    "contracts/PerformanceMetricsOracle.sol:PerformanceMetricsOracle"
  );

  console.log("All contracts deployed and verified successfully!");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });