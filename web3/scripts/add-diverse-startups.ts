import { ethers } from "hardhat";
import { parseEther } from "ethers/lib/utils";
import * as deployedContracts from "../deployed-contracts.json";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Adding startup data with account:", deployer.address);
  
  // Get the deployed Startup contract
  const Startup = await ethers.getContractFactory("Startup");
  const startupContract = await Startup.attach(deployedContracts.startup);

  const startups = [
    {
      name: "TechVision X",
      industry: "Artificial Intelligence",
      funding: "Series A",
      details: "Revolutionary AI platform for autonomous decision making in enterprise systems",
      arr: parseEther("5000000"), // $5M
      mrr: parseEther("416666"), // ~$417K
      cogs: 25,
      marketing: 15,
      cac: 8,
      logistics: 5,
      grossMargin: 75,
      ebitda: 18,
      salaries: 20,
      misc: 4,
      pat: 10
    },
    {
      name: "GreenEnergy Solutions",
      industry: "CleanTech",
      funding: "Series B",
      details: "Innovative renewable energy storage solutions for sustainable future",
      arr: parseEther("15000000"), // $15M
      mrr: parseEther("1250000"), // $1.25M
      cogs: 30,
      marketing: 12,
      cac: 6,
      logistics: 10,
      grossMargin: 70,
      ebitda: 15,
      salaries: 18,
      misc: 3,
      pat: 11
    },
    {
      name: "HealthTech Pro",
      industry: "Healthcare",
      funding: "Series A",
      details: "AI-powered diagnostic platform for early disease detection",
      arr: parseEther("8000000"), // $8M
      mrr: parseEther("666666"), // ~$667K
      cogs: 22,
      marketing: 14,
      cac: 7,
      logistics: 6,
      grossMargin: 78,
      ebitda: 20,
      salaries: 22,
      misc: 2,
      pat: 12
    },
    {
      name: "FinNext",
      industry: "FinTech",
      funding: "Series C",
      details: "Decentralized lending platform with AI-driven risk assessment",
      arr: parseEther("25000000"), // $25M
      mrr: parseEther("2083333"), // ~$2.08M
      cogs: 18,
      marketing: 16,
      cac: 9,
      logistics: 4,
      grossMargin: 82,
      ebitda: 25,
      salaries: 19,
      misc: 2,
      pat: 15
    },
    {
      name: "EduVerse",
      industry: "EdTech",
      funding: "Series B",
      details: "Immersive learning platform using AR/VR technology",
      arr: parseEther("12000000"), // $12M
      mrr: parseEther("1000000"), // $1M
      cogs: 28,
      marketing: 13,
      cac: 8,
      logistics: 7,
      grossMargin: 72,
      ebitda: 16,
      salaries: 21,
      misc: 3,
      pat: 9
    }
  ];

  console.log("Adding diverse startup data to the blockchain on Open Campus testnet...");

  for (const startup of startups) {
    try {
      const tx = await startupContract.registerStartup(
        startup.name,
        startup.industry,
        startup.funding,
        startup.details,
        startup.arr,
        startup.mrr,
        startup.cogs,
        startup.marketing,
        startup.cac,
        startup.logistics,
        startup.grossMargin,
        startup.ebitda,
        startup.salaries,
        startup.misc,
        startup.pat
      );
      
      await tx.wait();
      console.log(`Added startup: ${startup.name}`);
    } catch (error) {
      console.error(`Error adding startup ${startup.name}:`, error);
    }
  }

  console.log("Completed adding startup data");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });