import { verifyIAMRolePolicy, IAMRolePolicy } from '../verify-iam-role-policy';

describe('verifyIAMRolePolicy', () => {
	test('should return false if Resource field contains single asterisk', () => {
		const policy: IAMRolePolicy = {
			PolicyName: 'ExamplePolicy',
			PolicyDocument: {
				Version: '2012-10-17',
				Statement: [
					{
						Action: 's3:GetObject',
						Effect: 'Allow',
						Resource: '*',
					},
				],
			},
		};
		const jsonData = JSON.stringify(policy);

		const result = verifyIAMRolePolicy(jsonData);

		expect(result).toBe(false);
	});

	test('should return true if Resource field contains asterisk with other letters', () => {
		const policy: IAMRolePolicy = {
			PolicyName: 'ExamplePolicy',
			PolicyDocument: {
				Version: '2012-10-17',
				Statement: [
					{
						Action: 's3:GetObject',
						Effect: 'Allow',
						Resource: 'test:*',
					},
				],
			},
		};
		const jsonData = JSON.stringify(policy);

		const result = verifyIAMRolePolicy(jsonData);

		expect(result).toBe(true);
	});

	test('should return true if Resource field has no asterisk', () => {
		const policy: IAMRolePolicy = {
			PolicyName: 'ExamplePolicy',
			PolicyDocument: {
				Version: '2012-10-17',
				Statement: [
					{
						Action: 's3:GetObject',
						Effect: 'Allow',
						Resource: 'arn:aws:s3:::example-bucket',
					},
				],
			},
		};
		const jsonData = JSON.stringify(policy);

		const result = verifyIAMRolePolicy(jsonData);

		expect(result).toBe(true);
	});

	test('should return false if Resource filed is an array with single asterisk', () => {
		const policy: IAMRolePolicy = {
			PolicyName: 'ExamplePolicy',
			PolicyDocument: {
				Version: '2012-10-17',
				Statement: [
					{
						Action: 's3:GetObject',
						Effect: 'Allow',
						Resource: ['arn:aws:s3:::example-bucket', '*'],
					},
				],
			},
		};
		const jsonData = JSON.stringify(policy);

		const result = verifyIAMRolePolicy(jsonData);

		expect(result).toBe(false);
	});

	test('should return true if Resource field is an array without asterisk', () => {
		const policy: IAMRolePolicy = {
			PolicyName: 'ExamplePolicy',
			PolicyDocument: {
				Version: '2012-10-17',
				Statement: [
					{
						Action: 's3:GetObject',
						Effect: 'Allow',
						Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket2'],
					},
				],
			},
		};
		const jsonData = JSON.stringify(policy);

		const result = verifyIAMRolePolicy(jsonData);

		expect(result).toBe(true);
	});

	test('should return true if Resource field is an array with asterisk and other letters', () => {
		const policy: IAMRolePolicy = {
			PolicyName: 'ExamplePolicy',
			PolicyDocument: {
				Version: '2012-10-17',
				Statement: [
					{
						Action: 's3:GetObject',
						Effect: 'Allow',
						Resource: ['arn:aws:s3:::example-bucket', 'test:*'],
					},
				],
			},
		};
		const jsonData = JSON.stringify(policy);

		const result = verifyIAMRolePolicy(jsonData);

		expect(result).toBe(true);
	});

	test('should return true if Resource field is not a string or array', () => {
		const policy: IAMRolePolicy = {
			PolicyName: 'ExamplePolicy',
			PolicyDocument: {
				Version: '2012-10-17',
				Statement: [
					{
						Action: 's3:GetObject',
						Effect: 'Allow',
						Resource: 123 as any,
					},
				],
			},
		};
		const jsonData = JSON.stringify(policy);

		const result = verifyIAMRolePolicy(jsonData);

		expect(result).toBe(true);
	});

	test('should return true if Resource field is an empty string', () => {
		const policy: IAMRolePolicy = {
			PolicyName: 'ExamplePolicy',
			PolicyDocument: {
				Version: '2012-10-17',
				Statement: [
					{
						Action: 's3:GetObject',
						Effect: 'Allow',
						Resource: '',
					},
				],
			},
		};
		const jsonData = JSON.stringify(policy);

		const result = verifyIAMRolePolicy(jsonData);

		expect(result).toBe(true);
	});

	test('should return true if Statement field is an empty array', () => {
		const policy: IAMRolePolicy = {
			PolicyName: 'ExamplePolicy',
			PolicyDocument: {
				Version: '2012-10-17',
				Statement: [],
			},
		};
		const jsonData = JSON.stringify(policy);

		const result = verifyIAMRolePolicy(jsonData);

		expect(result).toBe(true);
	});

	test('should return false if one of the Resource fields contains single asterisk', () => {
		const policy: IAMRolePolicy = {
			PolicyName: 'ExamplePolicy',
			PolicyDocument: {
				Version: '2012-10-17',
				Statement: [
					{
						Action: 's3:GetObject',
						Effect: 'Allow',
						Resource: 'arn:aws:s3:::example-bucket',
					},
					{
						Action: 's3:GetObject',
						Effect: 'Allow',
						Resource: '*',
					},
				],
			},
		};
		const jsonData = JSON.stringify(policy);

		const result = verifyIAMRolePolicy(jsonData);

		expect(result).toBe(false);
	});
});
