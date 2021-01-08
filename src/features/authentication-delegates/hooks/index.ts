import { hooks, errors } from '@balena/pinejs';
import * as uuid from 'uuid';

// reconstitute the value into a properly formatted UUID...
const toUuid = (strippedUuid: string): string => {
	if (strippedUuid.length !== 32) {
		return '';
	}

	const parts: string[] = [];
	parts.push(strippedUuid.substr(0, 8));
	parts.push(strippedUuid.substr(8, 4));
	parts.push(strippedUuid.substr(12, 4));
	parts.push(strippedUuid.substr(16, 4));
	parts.push(strippedUuid.substr(20, 12));
	return parts.join('-');
};

hooks.addPureHook('POST', 'resin', 'authentication delegate', {
	POSTPARSE: async (args) => {
		const { request } = args;

		request.values.uuid = (request.values.uuid ?? uuid.v4()).replace(/-/g, '');

		const appUuid = toUuid(request.values.uuid);
		if (!uuid.validate(appUuid) || uuid.version(appUuid) !== 4) {
			throw new errors.BadRequestError(
				'Application UUID must be a 32 character long lower case UUID version 4.',
			);
		}
	},
});
