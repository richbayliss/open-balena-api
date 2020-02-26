import 'mocha';

import * as _ from 'lodash';

import { app } from '../../init';
import { Admin, getAdminUser } from '../test-lib/api-helpers';
import { expect } from '../test-lib/chai';
import * as fakeDevice from '../test-lib/fake-device';
import { default as supertest, SupertestUser } from '../test-lib/supertest';

interface MockReleaseParams {
	belongs_to__application: number;
	is_created_by__user: number;
	commit: string;
	composition: string;
	status: string;
	source: string;
	build_log: string;
	start_timestamp: number;
	end_timestamp?: number;
	update_timestamp?: number;
}
interface MockImageParams {
	is_a_build_of__service: number;
	start_timestamp: number;
	end_timestamp: number;
	push_timestamp: number;
	status: string;
	image_size: number;
	project_type?: string;
	error_message?: string;
	build_log: string;
}
interface MockServiceParams {
	application: number;
	service_name: string;
}

type MockRelease = MockReleaseParams & { id: number };
type MockImage = MockImageParams & { id: number };
type MockService = MockServiceParams & { id: number };

const addReleaseToApp = async (
	auth: SupertestUser,
	release: MockReleaseParams,
): Promise<MockRelease> =>
	(
		await supertest(app, auth)
			.post(`/resin/release`)
			.send(release)
			.expect(201)
	).body;

const addImageToService = async (
	auth: SupertestUser,
	image: MockImageParams,
): Promise<MockImage> =>
	(
		await supertest(app, auth)
			.post(`/resin/image`)
			.send(image)
			.expect(201)
	).body;

const addServiceToApp = async (
	auth: SupertestUser,
	serviceName: string,
	application: number,
): Promise<MockService> =>
	(
		await supertest(app, auth)
			.post(`/resin/service`)
			.send({
				application,
				service_name: serviceName,
			})
			.expect(201)
	).body;

const addImageToRelease = async (
	auth: SupertestUser,
	imageId: number,
	releaseId: number,
): Promise<void> => {
	await supertest(app, auth)
		.post(`/resin/image__is_part_of__release`)
		.send({
			image: imageId,
			is_part_of__release: releaseId,
		})
		.expect(201);
};

describe('Device with missing service installs', () => {
	let admin: Admin;
	let applicationId: number = 0;
	let device: fakeDevice.Device;
	const releases: _.Dictionary<number> = {};
	const services: _.Dictionary<number> = {};

	before('Setup the application and initial release', async function() {
		// login as the superuser...
		admin = await getAdminUser();

		// create an application...
		const { body: application } = await supertest(app, admin)
			.post('/resin/application')
			.send({
				device_type: 'intel-nuc',
				app_name: 'test-app-1',
			})
			.expect(201);

		applicationId = application.id;

		// add a release to the application...
		const { id: releaseId } = await addReleaseToApp(admin, {
			belongs_to__application: applicationId,
			is_created_by__user: 2,
			build_log: '',
			commit: 'deadbeef',
			composition: '',
			source: '',
			status: 'success',
			start_timestamp: Date.now(),
		});
		releases['deadbeef'] = releaseId;

		const { id: serviceId } = await addServiceToApp(
			admin,
			'service-1',
			applicationId,
		);
		services['service-1'] = serviceId;

		const { id: imageId } = await addImageToService(admin, {
			is_a_build_of__service: serviceId,
			build_log: '',
			start_timestamp: Date.now(),
			end_timestamp: Date.now(),
			push_timestamp: Date.now(),
			image_size: 1024,
			status: 'success',
		});
		await addImageToRelease(admin, imageId, releaseId);
	});

	it('should add a new device', async function() {
		device = await fakeDevice.provisionDevice(admin, applicationId);

		const state = await device.getStateV2();
		expect(state.local.apps[applicationId]).to.have.property(
			'commit',
			'deadbeef',
			"The device isn't running the current application default release",
		);
	});

	it('should pin the device to the first release', async function() {
		await supertest(app, admin)
			.patch(`/resin/device(${device.id})`)
			.send({
				should_be_running__release: releases['deadbeef'],
			})
			.expect(200);

		const state = await device.getStateV2();
		expect(state.local.apps[applicationId]).to.have.property(
			'commit',
			'deadbeef',
			"The device isn't running the pinned release",
		);
	});

	it('should add a new release to the application', async function() {
		// add a release to the application...
		const { id: releaseId } = await addReleaseToApp(admin, {
			belongs_to__application: applicationId,
			is_created_by__user: 2,
			build_log: '',
			commit: 'abcd0001',
			composition: '',
			source: '',
			status: 'success',
			start_timestamp: Date.now(),
		});
		releases['abcd0001'] = releaseId;

		const { id: firstImageId } = await addImageToService(admin, {
			is_a_build_of__service: services['service-1'],
			build_log: '',
			start_timestamp: Date.now(),
			end_timestamp: Date.now(),
			push_timestamp: Date.now(),
			image_size: 1024,
			status: 'success',
		});
		await addImageToRelease(admin, firstImageId, releaseId);

		const { id: secondServiceId } = await addServiceToApp(
			admin,
			'service-2',
			applicationId,
		);
		services['service-2'] = secondServiceId;
		const { id: secondImageId } = await addImageToService(admin, {
			is_a_build_of__service: secondServiceId,
			build_log: '',
			start_timestamp: Date.now(),
			end_timestamp: Date.now(),
			push_timestamp: Date.now(),
			image_size: 1024,
			status: 'success',
		});
		await addImageToRelease(admin, secondImageId, releaseId);

		const state = await device.getStateV2();
		expect(state.local.apps[applicationId]).to.have.property(
			'commit',
			'deadbeef',
			"The device isn't running the pinned release",
		);
	});

	it('should un-pin the device', async function() {
		await supertest(app, admin)
			.patch(`/resin/device(${device.id})`)
			.send({
				should_be_running__release: null,
			})
			.expect(200);
	});

	it('should pull the intended state', async function() {
		const state = await device.getStateV2();
		expect(state.local.apps[applicationId]).to.have.property(
			'commit',
			'abcd0001',
			"The device isn't running the default application release",
		);
	});

	after(async () => {
		await supertest(app, admin)
			.delete(`/resin/application(${applicationId})`)
			.expect(200);
	});
});
