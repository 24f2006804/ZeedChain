import { ethers } from "hardhat";
import deployedContracts from "../deployed-contracts.json";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Configuring contracts with account:", deployer.address);

  // Get contract instances
  const equityNFTFactory = await ethers.getContractAt("EquityNFTFactory", deployedContracts.equityNFTFactory);
  const fractionalInvestment = await ethers.getContractAt("FractionalInvestment", deployedContracts.fractionalInvestment);
  const startupValidation = await ethers.getContractAt("StartupValidation", deployedContracts.startupValidation);

  // Configure EquityNFTFactory
  console.log("Adding deployer as validator in EquityNFTFactory...");
  const isValidator = await equityNFTFactory.validators(deployer.address);
  if (!isValidator) {
    const tx = await equityNFTFactory.addValidator(deployer.address);
    await tx.wait();
    console.log("Added deployer as validator in EquityNFTFactory");
  } else {
    console.log("Deployer is already a validator in EquityNFTFactory");
  }

  // Configure StartupValidation
  console.log("Adding deployer as validator in StartupValidation...");
  const validatorInfo = await startupValidation.validators(deployer.address);
  if (!validatorInfo.isActive) {
    const tx = await startupValidation.addValidator(
      deployer.address,
      "Initial Validator",
      "Platform Admin"
    );
    await tx.wait();
    console.log("Added deployer as validator in StartupValidation");
  } else {
    console.log("Deployer is already a validator in StartupValidation");
  }

  // Verify FractionalInvestment permissions
  console.log("Verifying FractionalInvestment permissions...");
  const equityFactoryAddress = await fractionalInvestment.equityFactory();
  if (equityFactoryAddress.toLowerCase() !== deployedContracts.equityNFTFactory.toLowerCase()) {
    console.error("FractionalInvestment has incorrect EquityNFTFactory address");
  } else {
    console.log("FractionalInvestment permissions are correctly configured");
  }

  console.log("Post-deployment configuration completed");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });