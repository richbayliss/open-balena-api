import * as _ from 'lodash';
import { expect } from './test-lib/chai';
import * as fixtures from './test-lib/fixtures';
import { supertest } from './test-lib/supertest';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import { v4 as uuid4 } from 'uuid'

function createKeypair() {
	return new Promise<{
		publicKey: string,
		privateKey: string
	}>((resolve, reject) => {
	crypto.generateKeyPair('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: {
		  type: 'spki',
		  format: 'pem'
		},
		privateKeyEncoding: {
		  type: 'pkcs8',
		  format: 'pem',
		}
	  }, (err, publicKey, privateKey) => {
		  if (!err) {
			  return resolve({
				  publicKey,
				  privateKey
			  })
		  }

		  reject(err);
	  });
	});
}

describe('Authentication Delegates', function () {
	before(async function () {
		const fx = await fixtures.load('13-authentication-delegates');
		this.loadedFixtures = fx;
		this.user = fx.users.admin;
	});

	after(async function () {
		await fixtures.clean(this.loadedFixtures)
	});

	describe('Basic CRUD', () => {
		it('should create a delegate', async function () {
			const keys = await createKeypair();
			this.keys = keys;

			const uuid = uuid4().replace(/-/g, '');
			this.uuid = uuid;

			const { body } = await supertest(this.user)
				.post(`/resin/authentication_delegate`)
				.send({
					uuid,
					public_key: keys.publicKey
				})
				.expect(201);

			console.log('New Delegate:', body)
			expect(body).is.not.undefined;
			expect(body).has.property('uuid').that.is.not.null;
			expect(body).has.property('public_key').which.equals(keys.publicKey);
		});

		it('should accept a token from the new delegate', async function() {
			const { SUPERUSER_EMAIL: userId } = await import(
				'../src/lib/config'
			);

			const { privateKey } = this.keys;
			const { uuid: delegateUuid } = this;

			const token = jwt.sign({
				delegateUuid,
				userId,
			}, privateKey, {
				algorithm: 'RS256'
			});

			const { body: { sessionToken } } = await supertest()
				.post('/auth/delegate/exchange')
				.send({
					token
				})
				.expect(200);

			expect(sessionToken).is.not.undefined;
			
			// confirm the token works...
			await supertest({ token: sessionToken })
				.get('/resin/application')
				.expect(200);
		})
	});
});
