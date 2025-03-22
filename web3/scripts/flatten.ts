import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';

const execAsync = promisify(exec);

async function main() {
    // Create flattened directory if it doesn't exist
    const flattenedDir = path.join(__dirname, '../flattened');
    if (!fs.existsSync(flattenedDir)) {
        fs.mkdirSync(flattenedDir);
    }

    // List of contracts to flatten
    const contracts = [
        'EquityNFTFactory',
        'FractionalInvestment',
        'DynamicValuation',
        'StartupValidation',
        'StakeholderGovernance',
        'ProfitDistribution',
        'AIAdvisorIntegration',
        'FinancialDataOracle',
        'VerificationOracle',
        'PerformanceMetricsOracle'
    ];

    for (const contract of contracts) {
        console.log(`Flattening ${contract}...`);
        try {
            const outputPath = path.join(flattenedDir, `${contract}.sol`);
            await execAsync(`npx hardhat flatten contracts/${contract}.sol > ${outputPath}`);
            console.log(`${contract} flattened successfully`);
        } catch (error) {
            console.error(`Error flattening ${contract}:`, error);
        }
    }
}

main()
    .then(() => process.exit(0))
    .catch(error => {
        console.error(error);
        process.exit(1);
    });