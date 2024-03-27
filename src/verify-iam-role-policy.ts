export interface IAMRolePolicyStatement {
	Sid?: string;
	Effect: 'Allow' | 'Deny';
	Action: string | string[];
	Resource?: string | string[];
	Principal?: {
		[key: string]: string | string[];
	};
	Condition?: {
		[key: string]: {
			[key: string]: string;
		};
	};
}

export interface IAMRolePolicy {
	PolicyName: string;
	PolicyDocument: {
		Version: string;
		Statement: IAMRolePolicyStatement[];
	};
}

export function verifyIAMRolePolicy(jsonData: string): boolean {
	const iamRolePolicy = JSON.parse(jsonData) as IAMRolePolicy;

	for (const statement of iamRolePolicy.PolicyDocument.Statement) {
		if (typeof statement.Resource === 'string') {
			if (statement.Resource === '*') {
				return false;
			}

			continue;
		}

		if (Array.isArray(statement.Resource)) {
			if (statement.Resource.includes('*')) {
				return false;
			}
		}
	}

	return true;
}
