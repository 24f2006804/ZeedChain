import { ethers } from "hardhat";
import fs from "fs";
import path from "path";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with account:", deployer.address);

  // Deploy KYC contract
  const KYC = await ethers.getContractFactory("KYC");
  const kyc = await KYC.deploy();
  await kyc.deployed();
  console.log("KYC contract deployed to:", kyc.address);

  // Deploy Startup contract
  const Startup = await ethers.getContractFactory("Startup");
  const startup = await Startup.deploy(kyc.address);
  await startup.deployed();
  console.log("Startup contract deployed to:", startup.address);

  // Update deployed-contracts.json
  const deployedContractsPath = path.join(__dirname, "..", "deployed-contracts.json");
  let deployedContracts = {};
  
  if (fs.existsSync(deployedContractsPath)) {
    const content = fs.readFileSync(deployedContractsPath, "utf8");
    deployedContracts = JSON.parse(content);
  }

  deployedContracts.kyc = kyc.address;
  deployedContracts.startup = startup.address;

  fs.writeFileSync(
    deployedContractsPath,
    JSON.stringify(deployedContracts, null, 2)
  );

  console.log("Deployment complete and contracts.json updated");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });