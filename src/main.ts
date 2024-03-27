import * as fs from 'fs';
import { verifyIAMRolePolicy } from './verify-iam-role-policy';


try {
	const filename = process.argv[2];
	if (!filename) {
		throw new Error('Please provide a JSON file to parse');
	}

	if (!fs.existsSync(filename)) {
		throw new Error(`File ${filename} does not exist`);
	}

	const jsonData = fs.readFileSync(filename, 'utf-8');

	const result = verifyIAMRolePolicy(jsonData);
	console.log('Result:', result);
} catch (error) {
	console.error('Error reading or parsing JSON file:', error.message);
}
